package br.org.caixa;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class PublicKeyCache {

    private final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Logger LOGGER = Logger.getLogger(PublicKeyCache.class.getName());

    public PublicKey getPublicKey(String kid) {
        if (!publicKeys.containsKey(kid)) {
            refreshKeys();
        }
        return publicKeys.get(kid);
    }

    public void refreshKeys() {
        try {
            String jwksJson = fetchJwksFromServer();
            JsonNode jwks = objectMapper.readTree(jwksJson);
            JsonNode keys = jwks.get("keys");
            for (JsonNode key : keys) {
                String kid = key.get("kid").asText();
                String rsaPublicKey = key.get("x5c").asText().replaceAll("-----BEGIN PUBLIC KEY-----", "")
                                                .replaceAll("-----END PUBLIC KEY-----", "")
                                                .replaceAll("\\s+", "");
                byte[] encoded = Base64.getDecoder().decode(rsaPublicKey);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
                publicKeys.put(kid, publicKey);
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error refreshing keys", e);
        }
    }
    
    private String fetchJwksFromServer() {
        String url = "https://keycloak-server/auth/realms/{realm-name}/protocol/openid-connect/certs";
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (IOException | InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Failed to fetch JWKS", e);
            return null;
        }
    }
}
