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





Here is everything:

---

**1. `TransactionRequest.java`**
```java
package com.aaas.model;

import jakarta.validation.constraints.*;

public class TransactionRequest {

    @NotBlank(message = "email is required")
    @Email(message = "email must be valid")
    private String email;

    @NotNull(message = "amount is required")
    @Min(value = 100, message = "amount must be at least 100 kobo (₦1.00)")
    private Long amount;

    public String getEmail()  { return email; }
    public Long   getAmount() { return amount; }
    public void setEmail(String email)   { this.email = email; }
    public void setAmount(Long amount)   { this.amount = amount; }
}
```

---

**2. `TransactionResponse.java`**
```java
package com.aaas.model;

public class TransactionResponse {

    private boolean status;
    private String  message;
    private Data    data;

    public static class Data {
        private final String authorizationUrl;
        private final String accessCode;
        private final String reference;

        public Data(String authorizationUrl, String accessCode, String reference) {
            this.authorizationUrl = authorizationUrl;
            this.accessCode       = accessCode;
            this.reference        = reference;
        }

        public String getAuthorizationUrl() { return authorizationUrl; }
        public String getAccessCode()       { return accessCode; }
        public String getReference()        { return reference; }
    }

    public TransactionResponse(boolean status, String message, Data data) {
        this.status  = status;
        this.message = message;
        this.data    = data;
    }

    public boolean isStatus()  { return status; }
    public String getMessage() { return message; }
    public Data   getData()    { return data; }
}
```

---

**3. `Transaction.java`**
```java
package com.aaas.model;

import java.time.LocalDateTime;

public class Transaction {

    private Long          id;
    private String        merchantId;
    private String        customerEmail;
    private Long          amountKobo;
    private String        reference;
    private String        accessCode;
    private String        environment;
    private String        status;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Getters
    public Long          getId()            { return id; }
    public String        getMerchantId()    { return merchantId; }
    public String        getCustomerEmail() { return customerEmail; }
    public Long          getAmountKobo()    { return amountKobo; }
    public String        getReference()     { return reference; }
    public String        getAccessCode()    { return accessCode; }
    public String        getEnvironment()   { return environment; }
    public String        getStatus()        { return status; }
    public LocalDateTime getCreatedAt()     { return createdAt; }
    public LocalDateTime getUpdatedAt()     { return updatedAt; }

    // Setters
    public void setId(Long id)                        { this.id = id; }
    public void setMerchantId(String merchantId)      { this.merchantId = merchantId; }
    public void setCustomerEmail(String email)         { this.customerEmail = email; }
    public void setAmountKobo(Long amountKobo)         { this.amountKobo = amountKobo; }
    public void setReference(String reference)         { this.reference = reference; }
    public void setAccessCode(String accessCode)       { this.accessCode = accessCode; }
    public void setEnvironment(String environment)     { this.environment = environment; }
    public void setStatus(String status)               { this.status = status; }
    public void setCreatedAt(LocalDateTime createdAt)  { this.createdAt = createdAt; }
    public void setUpdatedAt(LocalDateTime updatedAt)  { this.updatedAt = updatedAt; }
}
```

---

**4. `TransactionRepository.java`**
```java
package com.aaas.db;

import com.aaas.model.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface TransactionRepository extends JpaRepository<Transaction, Long> {

    @Query("SELECT t FROM Transaction t WHERE t.reference = :reference")
    Optional<Transaction> findByReference(@Param("reference") String reference);
}
```

---

**5. `TransactionService.java`**
```java
package com.aaas.service;

import com.aaas.db.TransactionRepository;
import com.aaas.model.Transaction;
import com.aaas.model.TransactionRequest;
import com.aaas.model.TransactionResponse;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class TransactionService {

    private final TransactionRepository transactionRepository;
    private static final String CHECKOUT_BASE_URL = "https://checkout.yourplatform.com/";

    public TransactionService(TransactionRepository transactionRepository) {
        this.transactionRepository = transactionRepository;
    }

    public TransactionResponse initialize(String merchantId,
                                          String environment,
                                          TransactionRequest request) {

        // Step 1: Generate unique reference and access code
        String reference  = "txn_"  + UUID.randomUUID().toString().replace("-", "");
        String accessCode = "auth_" + UUID.randomUUID().toString().replace("-", "");

        // Step 2: Build transaction record
        Transaction transaction = new Transaction();
        transaction.setMerchantId(merchantId);
        transaction.setCustomerEmail(request.getEmail());
        transaction.setAmountKobo(request.getAmount());
        transaction.setReference(reference);
        transaction.setAccessCode(accessCode);
        transaction.setEnvironment(environment);
        transaction.setStatus("pending");
        transaction.setCreatedAt(LocalDateTime.now());
        transaction.setUpdatedAt(LocalDateTime.now());

        // Step 3: Save to DB
        transactionRepository.save(transaction);

        // Step 4: Return response
        return new TransactionResponse(
            true,
            "Authorization URL initialized",
            new TransactionResponse.Data(
                CHECKOUT_BASE_URL + accessCode,
                accessCode,
                reference
            )
        );
    }
}
```

---

**6. `TransactionController.java`**
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

    /**
     * POST /v1/transaction/initialize
     * Authorization: Bearer sk_live_...
     *
     * Body:
     * {
     *   "email":  "customer@email.com",
     *   "amount": 50000
     * }
     */
    @PostMapping("/transaction/initialize")
    public ResponseEntity<TransactionResponse> initialize(
            @Valid @RequestBody TransactionRequest request,
            HttpServletRequest httpRequest) {

        // Injected by ApiKeyAuthFilter — never from client
        String merchantId  = (String) httpRequest.getAttribute("merchantId");
        String environment = (String) httpRequest.getAttribute("environment");

        TransactionResponse response =
            transactionService.initialize(merchantId, environment, request);

        return ResponseEntity.ok(response);
    }
}
```

---

**7. `ApiKeyCacheService.java`**
```java
package com.aaas.cache;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class ApiKeyCacheService {

    private static final String CACHE_PREFIX = "cache:apikey:";
    private static final long   TTL_MINUTES  = 10;

    private final RedisTemplate<String, String> redisTemplate;

    public ApiKeyCacheService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /** Store hash in Redis with TTL */
    public void store(String hash, String merchantId) {
        redisTemplate.opsForValue().set(
            CACHE_PREFIX + hash,
            merchantId,
            TTL_MINUTES,
            TimeUnit.MINUTES
        );
    }

    /** Get merchantId from cache by hash */
    public String get(String hash) {
        return redisTemplate.opsForValue().get(CACHE_PREFIX + hash);
    }

    /** Evict key from cache immediately on revocation */
    public void evict(String hash) {
        redisTemplate.delete(CACHE_PREFIX + hash);
    }
}
```

---

**8. `NotificationService.java`**
```java
package com.aaas.notify;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {

    private final JavaMailSender mailSender;

    public NotificationService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    /**
     * Sends revocation alert email to merchant.
     * Called immediately after key is revoked.
     */
    public void sendKeyRevocationAlert(String merchantId, String keyHash) {
        SimpleMailMessage mail = new SimpleMailMessage();
        mail.setTo(merchantId);
        mail.setSubject("AaaS — API Key Revoked");
        mail.setText(
            "Hello,\n\n" +
            "Your API key ending in " + keyHash.substring(0, 8) + "... " +
            "has been revoked.\n\n" +
            "If you did not request this, please contact support immediately.\n\n" +
            "To generate a new key, log in to your dashboard.\n\n" +
            "AaaS Platform"
        );
        mailSender.send(mail);
    }
}
```

---

**9. `RateLimitFilter.java`**
```java
package com.aaas.auth;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final int    MAX_REQUESTS = 100;   // per minute
    private static final String PREFIX       = "ratelimit:";

    private final RedisTemplate<String, String> redisTemplate;

    public RateLimitFilter(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        // Only rate limit requests with a Bearer token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Use the key itself as the rate limit identifier
        String rawKey     = authHeader.substring(7);
        String redisKey   = PREFIX + rawKey;

        // Get current request count from Redis
        String countStr   = redisTemplate.opsForValue().get(redisKey);
        int    count      = countStr != null ? Integer.parseInt(countStr) : 0;

        if (count >= MAX_REQUESTS) {
            // Reject — too many requests
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"status\": false, \"message\": \"Rate limit exceeded. Maximum 100 requests/minute.\"}"
            );
            return;
        }

        // Increment count — reset after 1 minute
        if (count == 0) {
            redisTemplate.opsForValue().set(redisKey, "1", 1, TimeUnit.MINUTES);
        } else {
            redisTemplate.opsForValue().increment(redisKey);
        }

        filterChain.doFilter(request, response);
    }
}
```

---

**Complete file list:**

| # | File | Package |
|---|---|---|
| 1 | `ApiKeyEngine.java` | `com.aaas.auth` |
| 2 | `MerchantApiKey.java` | `com.aaas.model` |
| 3 | `ProvisionedKeyResponse.java` | `com.aaas.model` |
| 4 | `ApiKeyProvisioningService.java` | `com.aaas.auth` |
| 5 | `MerchantApiKeyRepository.java` | `com.aaas.db` |
| 6 | `ApiKeyAuthFilter.java` | `com.aaas.auth` |
| 7 | `ApiKeyRevocationService.java` | `com.aaas.auth` |
| 8 | `ApiKeyController.java` | `com.aaas.controller` |
| 9 | `TransactionRequest.java` | `com.aaas.model` |
| 10 | `TransactionResponse.java` | `com.aaas.model` |
| 11 | `Transaction.java` | `com.aaas.model` |
| 12 | `TransactionRepository.java` | `com.aaas.db` |
| 13 | `TransactionService.java` | `com.aaas.service` |
| 14 | `TransactionController.java` | `com.aaas.controller` |
| 15 | `ApiKeyCacheService.java` | `com.aaas.cache` |
| 16 | `NotificationService.java` | `com.aaas.notify` |
| 17 | `RateLimitFilter.java` | `com.aaas.auth` |
