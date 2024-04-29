package br.org.caixa;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Base64;

//Objetivo: Esta classe implementa um filtro que intercepta requisições HTTP para verificar a presença e a validade de tokens JWT.

@Provider
@Priority(Priorities.AUTHENTICATION)
public class JWTTokenValidator implements ContainerRequestFilter {

    @Inject
    TokenValidationService tokenValidationService;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String token = requestContext.getHeaderString("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            try {
                // Suponhamos que queremos logar ou verificar algo no payload JSON do JWT (situação hipotética)
                JsonNode payload = objectMapper.readTree(new String(Base64.getDecoder().decode(token.split("\\.")[1])));
                // Apenas um exemplo de como acessar um campo
                String userId = payload.get("user_id").asText();

                if (!tokenValidationService.validateToken(token)) {
                    requestContext.abortWith(jakarta.ws.rs.core.Response.status(jakarta.ws.rs.core.Response.Status.UNAUTHORIZED).build());
                }
                // Pode adicionar mais lógica baseada no payload aqui
            } catch (IOException e) {
                requestContext.abortWith(jakarta.ws.rs.core.Response.status(jakarta.ws.rs.core.Response.Status.UNAUTHORIZED).build());
            }
        } else {
            requestContext.abortWith(jakarta.ws.rs.core.Response.status(jakarta.ws.rs.core.Response.Status.UNAUTHORIZED).build());
        }
    }
}
