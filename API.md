# CyberX API Documentation

## Overview
CyberX provides a real-time threat detection API that uses advanced machine learning algorithms to detect potential security threats in network traffic. The system uses an ensemble of models including Random Forest, Gradient Boosting, and Neural Networks for high accuracy and reduced false positives.

## Authentication
All API endpoints require authentication using JWT (JSON Web Token).

### Get API Token
```http
POST /api/login
Content-Type: application/json

{
    "api_key": "your-api-key"
}
```

Response:
```json
{
    "token": "your.jwt.token"
}
```

## API Endpoints

### 1. Analyze Traffic
Analyze network traffic for potential threats in real-time.

```http
POST /api/analyze
Authorization: Bearer your.jwt.token
Content-Type: application/json

{
    "traffic_data": [
        0,      // protocol_type
        0,      // service
        1500,   // src_bytes
        800,    // dst_bytes
        30      // duration
    ]
}
```

Response:
```json
{
    "is_threat": true,
    "confidence": 0.95,
    "threat_level": "high",
    "timestamp": "2025-05-04T12:00:00.000Z"
}
```

### 2. Get Recent Threats
Retrieve recent threat detections.

```http
GET /api/threats/recent?hours=24
Authorization: Bearer your.jwt.token
```

Response:
```json
{
    "threats": [
        {
            "is_threat": true,
            "confidence": 0.95,
            "threat_level": "high",
            "timestamp": "2025-05-04T12:00:00.000Z"
        }
    ],
    "count": 1
}
```

### 3. Get Statistics
Retrieve threat detection statistics.

```http
GET /api/stats
Authorization: Bearer your.jwt.token
```

Response:
```json
{
    "total_threats": 10,
    "threat_levels": {
        "high": 2,
        "medium": 3,
        "low": 4,
        "info": 1
    },
    "timeframe_hours": 24
}
```

## Web Application Integration

### JavaScript Example
```javascript
class CyberXClient {
    constructor(apiKey, baseUrl = 'http://your-api-url') {
        this.baseUrl = baseUrl;
        this.token = null;
        this.apiKey = apiKey;
    }

    async authenticate() {
        const response = await fetch(`${this.baseUrl}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ api_key: this.apiKey })
        });
        const data = await response.json();
        this.token = data.token;
    }

    async analyzeTraffic(trafficData) {
        if (!this.token) await this.authenticate();

        const response = await fetch(`${this.baseUrl}/api/analyze`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ traffic_data: trafficData })
        });
        return await response.json();
    }
}

// Usage
const client = new CyberXClient('your-api-key');
client.analyzeTraffic([0, 0, 1500, 800, 30])
    .then(result => {
        if (result.is_threat) {
            console.log(`Threat detected! Level: ${result.threat_level}`);
        }
    });
```

## Mobile Application Integration

### Android (Kotlin) Example
```kotlin
class CyberXClient(private val apiKey: String, private val baseUrl: String) {
    private var token: String? = null
    private val client = OkHttpClient()
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun authenticate() {
        val request = Request.Builder()
            .url("$baseUrl/api/login")
            .post(
                json.encodeToString(
                    mapOf("api_key" to apiKey)
                ).toRequestBody("application/json".toMediaType())
            )
            .build()

        client.newCall(request).execute().use { response ->
            token = json.decodeFromString<LoginResponse>(
                response.body!!.string()
            ).token
        }
    }

    suspend fun analyzeTraffic(trafficData: List<Int>): ThreatAnalysis {
        if (token == null) authenticate()

        val request = Request.Builder()
            .url("$baseUrl/api/analyze")
            .header("Authorization", "Bearer $token")
            .post(
                json.encodeToString(
                    mapOf("traffic_data" to trafficData)
                ).toRequestBody("application/json".toMediaType())
            )
            .build()

        return client.newCall(request).execute().use { response ->
            json.decodeFromString(response.body!!.string())
        }
    }
}
```

### iOS (Swift) Example
```swift
class CyberXClient {
    private let baseURL: URL
    private let apiKey: String
    private var token: String?
    
    init(apiKey: String, baseURL: URL) {
        self.apiKey = apiKey
        self.baseURL = baseURL
    }
    
    func authenticate() async throws {
        var request = URLRequest(url: baseURL.appendingPathComponent("api/login"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body = ["api_key": apiKey]
        request.httpBody = try JSONEncoder().encode(body)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        let response = try JSONDecoder().decode(LoginResponse.self, from: data)
        token = response.token
    }
    
    func analyzeTraffic(_ trafficData: [Int]) async throws -> ThreatAnalysis {
        if token == nil {
            try await authenticate()
        }
        
        var request = URLRequest(url: baseURL.appendingPathComponent("api/analyze"))
        request.httpMethod = "POST"
        request.setValue("Bearer \(token!)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body = ["traffic_data": trafficData]
        request.httpBody = try JSONEncoder().encode(body)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(ThreatAnalysis.self, from: data)
    }
}
```

## Rate Limits
- Login endpoint: 5 requests per minute
- Analysis endpoint: 10 requests per minute
- Other endpoints: 50 requests per hour

## Best Practices
1. **Cache Authentication Token**: Store and reuse the JWT token until it expires
2. **Handle Rate Limits**: Implement exponential backoff when rate limits are hit
3. **Error Handling**: Implement proper error handling for network issues and API errors
4. **Secure Storage**: Store API keys and tokens securely using platform-specific secure storage
5. **Monitor Usage**: Track API usage and implement alerts for unusual patterns

## Error Codes
- 401: Authentication error (invalid/missing token)
- 429: Rate limit exceeded
- 400: Invalid request format
- 500: Server error

## Support
For technical support or feature requests, please contact support@cyberx.com