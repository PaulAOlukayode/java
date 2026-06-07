Here is the entire flow in code from start to finish:

---

**1. `ApiKeyEngine.java`**
```java
package com.aaas.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class ApiKeyEngine {

    private static final String SECRET_PREFIX = "sk_live_";
    private static final String PUBLIC_PREFIX = "pk_live_";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final class TokenCluster {
        private final String rawSecretKey;
        private final String rawPublicKey;
        private final String databaseHash;
        private final String keyPrefix;

        public TokenCluster(String rawSecretKey, String rawPublicKey,
                            String databaseHash, String keyPrefix) {
            this.rawSecretKey = rawSecretKey;
            this.rawPublicKey = rawPublicKey;
            this.databaseHash = databaseHash;
            this.keyPrefix    = keyPrefix;
        }

        public String getRawSecretKey()  { return rawSecretKey; }
        public String getRawPublicKey()  { return rawPublicKey; }
        public String getDatabaseHash()  { return databaseHash; }
        public String getKeyPrefix()     { return keyPrefix; }
    }

    public static TokenCluster generateTokenCluster() {
        byte[] secretBytes = new byte[32];
        SECURE_RANDOM.nextBytes(secretBytes);
        String secretHex = bytesToHex(secretBytes);

        String checksum = computeSha256(secretHex).substring(0, 8);
        String rawSecretKey = SECRET_PREFIX + secretHex + "_" + checksum;

        byte[] pubBytes = new byte[16];
        SECURE_RANDOM.nextBytes(pubBytes);
        String rawPublicKey = PUBLIC_PREFIX + bytesToHex(pubBytes);

        String databaseHash = computeSha256(rawSecretKey);
        String keyPrefix = rawSecretKey.substring(0, 16);

        return new TokenCluster(rawSecretKey, rawPublicKey, databaseHash, keyPrefix);
    }

    public static boolean hasValidStructure(String incomingKey, String targetPrefix) {
        if (incomingKey == null || !incomingKey.startsWith(targetPrefix)) return false;
        String body = incomingKey.substring(targetPrefix.length());
        String[] segments = body.split("_");
        if (segments.length != 2) return false;
        String expectedChecksum = computeSha256(segments[0]).substring(0, 8);
        return expectedChecksum.equals(segments[1]);
    }

    public static boolean verifySecretKey(String incomingKey, String storedDbHash) {
        if (!hasValidStructure(incomingKey, SECRET_PREFIX)) return false;
        String calculatedHash = computeSha256(incomingKey);
        return MessageDigest.isEqual(
            calculatedHash.getBytes(StandardCharsets.UTF_8),
            storedDbHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    public static String computeSha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in JDK runtime", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private ApiKeyEngine() {}
}
```

---

**2. `MerchantApiKey.java`**
```java
package com.aaas.model;

public class MerchantApiKey {

    private Long id;
    private String merchantId;
    private String publicKey;
    private String hashedSecretKey;
    private String keyPrefix;
    private String label;
    private String environment;
    private String status;

    // Getters
    public Long getId()                { return id; }
    public String getMerchantId()      { return merchantId; }
    public String getPublicKey()       { return publicKey; }
    public String getHashedSecretKey() { return hashedSecretKey; }
    public String getKeyPrefix()       { return keyPrefix; }
    public String getLabel()           { return label; }
    public String getEnvironment()     { return environment; }
    public String getStatus()          { return status; }

    // Setters
    public void setId(Long id)                     { this.id = id; }
    public void setMerchantId(String merchantId)   { this.merchantId = merchantId; }
    public void setPublicKey(String publicKey)      { this.publicKey = publicKey; }
    public void setHashedSecretKey(String hash)     { this.hashedSecretKey = hash; }
    public void setKeyPrefix(String keyPrefix)      { this.keyPrefix = keyPrefix; }
    public void setLabel(String label)              { this.label = label; }
    public void setEnvironment(String environment)  { this.environment = environment; }
    public void setStatus(String status)            { this.status = status; }
}
```

---

**3. `ProvisionedKeyResponse.java`**
```java
package com.aaas.model;

public class ProvisionedKeyResponse {

    private final String rawSecretKey;
    private final String rawPublicKey;
    private final String keyPrefix;

    public ProvisionedKeyResponse(String rawSecretKey, String rawPublicKey, String keyPrefix) {
        this.rawSecretKey = rawSecretKey;
        this.rawPublicKey = rawPublicKey;
        this.keyPrefix    = keyPrefix;
    }

    public String getRawSecretKey() { return rawSecretKey; }
    public String getRawPublicKey() { return rawPublicKey; }
    public String getKeyPrefix()    { return keyPrefix; }
}
```

---

**4. `ApiKeyProvisioningService.java`**
```java
package com.aaas.auth;

import com.aaas.db.MerchantApiKeyRepository;
import com.aaas.model.MerchantApiKey;
import com.aaas.model.ProvisionedKeyResponse;

public class ApiKeyProvisioningService {

    private final MerchantApiKeyRepository keyRepository;

    public ApiKeyProvisioningService(MerchantApiKeyRepository keyRepository) {
        this.keyRepository = keyRepository;
    }

    public ProvisionedKeyResponse provision(String merchantId, String label, String environment) {

        // Step 1: Generate key cluster
        ApiKeyEngine.TokenCluster cluster = ApiKeyEngine.generateTokenCluster();

        // Step 2: Build DB record
        MerchantApiKey record = new MerchantApiKey();

        // From UI params
        record.setMerchantId(merchantId);
        record.setLabel(label);
        record.setEnvironment(environment);
        record.setStatus("active");

        // From TokenCluster getters
        record.setPublicKey(cluster.getRawPublicKey());
        record.setHashedSecretKey(cluster.getDatabaseHash());
        record.setKeyPrefix(cluster.getKeyPrefix());

        // Step 3: Save to DB — rawSecretKey never saved
        keyRepository.save(record);

        // Step 4: Return to UI — rawSecretKey shown ONCE
        return new ProvisionedKeyResponse(
            cluster.getRawSecretKey(),
            cluster.getRawPublicKey(),
            cluster.getKeyPrefix()
        );
    }
}
```

---

**5. `MerchantApiKeyRepository.java`**
```java
package com.aaas.db;

import com.aaas.model.MerchantApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface MerchantApiKeyRepository extends JpaRepository<MerchantApiKey, Long> {

    @Query("SELECT k FROM MerchantApiKey k " +
           "WHERE k.hashedSecretKey = :hash " +
           "AND k.status = 'active' " +
           "AND (k.expiresAt IS NULL OR k.expiresAt > CURRENT_TIMESTAMP)")
    Optional<MerchantApiKey> findActiveNonExpiredByHash(@Param("hash") String hash);

    @Modifying
    @Query("UPDATE MerchantApiKey k SET k.lastUsedAt = CURRENT_TIMESTAMP WHERE k.id = :id")
    void updateLastUsed(@Param("id") Long id);

    @Modifying
    @Query("UPDATE MerchantApiKey k SET k.status = 'revoked' WHERE k.hashedSecretKey = :hash")
    void revokeByHash(@Param("hash") String hash);
}
```

---

**6. `ApiKeyAuthFilter.java`**
```java
package com.aaas.auth;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.aaas.db.MerchantApiKeyRepository;
import com.aaas.model.MerchantApiKey;

import java.io.IOException;
import java.util.Optional;

@Component
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private static final String SECRET_PREFIX = "sk_live_";
    private final MerchantApiKeyRepository keyRepository;

    public ApiKeyAuthFilter(MerchantApiKeyRepository keyRepository) {
        this.keyRepository = keyRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        // Step 1: Check header exists
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            sendError(response, 401, "Missing API key. Send as: Authorization: Bearer sk_live_...");
            return;
        }

        // Step 2: Extract raw key
        String rawKey = authHeader.substring(7);

        // Step 3: Validate structure before DB call
        if (!ApiKeyEngine.hasValidStructure(rawKey, SECRET_PREFIX)) {
            sendError(response, 401, "Invalid API key format.");
            return;
        }

        // Step 4: Hash the incoming key
        String hash = ApiKeyEngine.computeSha256(rawKey);

        // Step 5: DB lookup
        Optional<MerchantApiKey> keyRecord =
            keyRepository.findActiveNonExpiredByHash(hash);

        if (keyRecord.isEmpty()) {
            sendError(response, 401, "Invalid or revoked API key.");
            return;
        }

        // Step 6: Update last used
        keyRepository.updateLastUsed(keyRecord.get().getId());

        // Step 7: Attach merchant context
        request.setAttribute("merchantId",  keyRecord.get().getMerchantId());
        request.setAttribute("keyScope",    keyRecord.get().getScope());
        request.setAttribute("environment", keyRecord.get().getEnvironment());

        filterChain.doFilter(request, response);
    }

    private void sendError(HttpServletResponse response, int status, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(
            "{\"status\": false, \"message\": \"" + message + "\"}"
        );
    }
}
```

---

**7. `TransactionRequest.java`**
```java
package com.aaas.model;

import jakarta.validation.constraints.*;

public class TransactionRequest {

    @NotBlank(message = "email is required")
    @Email(message = "email must be a valid email address")
    private String email;

    @NotNull(message = "amount is required")
    @Min(value = 100, message = "amount must be at least 100 kobo (₦1.00)")
    private Long amount;

    public String getEmail()  { return email; }
    public Long   getAmount() { return amount; }
    public void   setEmail(String email)   { this.email = email; }
    public void   setAmount(Long amount)   { this.amount = amount; }
}
```

---

**8. `TransactionController.java`**
```java
package com.aaas.controller;

import com.aaas.model.TransactionRequest;
import com.aaas.model.TransactionResponse;
import com.aaas.service.TransactionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1")
public class TransactionController {

    private final TransactionService transactionService;

    public TransactionController(TransactionService transactionService) {
        this.transactionService = transactionService;
    }

    @PostMapping("/transaction/initialize")
    public ResponseEntity<TransactionResponse> initialize(
            @Valid @RequestBody TransactionRequest request,
            HttpServletRequest httpRequest) {

        String merchantId  = (String) httpRequest.getAttribute("merchantId");
        String environment = (String) httpRequest.getAttribute("environment");

        TransactionResponse response =
            transactionService.initialize(merchantId, environment, request);

        return ResponseEntity.ok(response);
    }
}
```

---

**9. `ApiKeyRevocationService.java`**
```java
package com.aaas.auth;

import com.aaas.cache.ApiKeyCacheService;
import com.aaas.db.MerchantApiKeyRepository;
import com.aaas.notify.NotificationService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ApiKeyRevocationService {

    private final MerchantApiKeyRepository keyRepository;
    private final ApiKeyCacheService        cacheService;
    private final NotificationService       notificationService;

    public ApiKeyRevocationService(MerchantApiKeyRepository keyRepository,
                                   ApiKeyCacheService cacheService,
                                   NotificationService notificationService) {
        this.keyRepository       = keyRepository;
        this.cacheService        = cacheService;
        this.notificationService = notificationService;
    }

    @Transactional
    public void revoke(String hashedKey, String merchantId) {
        // Step 1: Revoke in DB
        keyRepository.revokeByHash(hashedKey);

        // Step 2: Evict from Redis cache
        cacheService.evict(hashedKey);

        // Step 3: Notify merchant
        notificationService.sendKeyRevocationAlert(merchantId, hashedKey);
    }
}
```

---

That is the entire codebase. Say **next** for Step 12 where we walk through how the transaction request is verified on your server.
