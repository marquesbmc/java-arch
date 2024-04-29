package br.org.caixa;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.eclipse.microprofile.jwt.JsonWebToken;

@ApplicationScoped
public class TokenValidationService {

    @Inject
    JsonWebToken jwt;
    @Inject
    PublicKeyCache publicKeyCache;
    @Inject
    JWTClaimsValidator claimsValidator;

    private static final Logger LOGGER = Logger.getLogger(TokenValidationService.class.getName());

    public boolean validateToken(String token) {
        try {
            if (jwt == null || jwt.getName().isEmpty()) {
                LOGGER.log(Level.WARNING, "JWT is invalid or empty");
                return false;
            }

            // Validar as claims do token
            if (!claimsValidator.validateClaims(jwt)) {
                return false;
            }

            String kid = jwt.getClaim("kid");
            PublicKey publicKey = publicKeyCache.getPublicKey(kid);
            if (publicKey == null) {
                LOGGER.log(Level.SEVERE, "No public key found for KID: {0}", kid);
                return false;
            }

            // Adicione a validação da assinatura aqui, se necessário
            return true;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error validating token: {0}", e.getMessage());
            return false;
        }
    }
}
