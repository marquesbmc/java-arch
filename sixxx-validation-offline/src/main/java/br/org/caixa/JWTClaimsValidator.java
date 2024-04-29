package br.org.caixa;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.jwt.JsonWebToken;
import java.util.logging.Level;
import java.util.logging.Logger;

@ApplicationScoped
public class JWTClaimsValidator {

    private static final Logger LOGGER = Logger.getLogger(JWTClaimsValidator.class.getName());

    public boolean validateClaims(JsonWebToken jwt) {
        try {
            // Verifica se o issuer é o esperado
            if (!"https://issuer.example.com".equals(jwt.getIssuer())) {
                LOGGER.log(Level.SEVERE, "Invalid issuer.");
                return false;
            }

            // Verifica se o token está expirado
            if (jwt.getExpirationTime() == 0 || System.currentTimeMillis() / 1000 > jwt.getExpirationTime()) {
                LOGGER.log(Level.SEVERE, "Token has expired or expiration is not set.");
                return false;
            }

            // Verifica se a audiência inclui o identificador esperado da aplicação
            if (!jwt.getAudience().contains("myApplicationId")) {
                LOGGER.log(Level.SEVERE, "Invalid audience.");
                return false;
            }

            // Adicionar mais verificações de claims conforme necessário
            return true;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error validating JWT claims: " + e.getMessage(), e);
            return false;
        }
    }
}
