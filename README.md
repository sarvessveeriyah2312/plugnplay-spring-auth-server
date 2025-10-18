# Reusable Authentication Server with Spring Boot and OAuth 2.0

This is a production-ready, reusable authentication server built with Spring Boot that supports OAuth 2.0 flows using Google, GitHub, and Microsoft as identity providers. It uses JWT tokens for stateless authentication and includes comprehensive error handling.

## Features

- 🔐 **OAuth 2.0 Support** - Google, GitHub, and Microsoft authentication
- 🎫 **JWT Authentication** - Stateless token-based authentication
- 📊 **User Management** - Automatic user creation and storage
- 🛡️ **Security** - Spring Security with OAuth 2.0 client configuration
- 🌐 **CORS Support** - Configurable Cross-Origin Resource Sharing
- 📝 **Error Handling** - Global exception handling with proper HTTP responses
- 🗄️ **Database** - JPA/H2 integration for user persistence
- 🔧 **H2 Console** - Built-in database console for development

## Technology Stack

- Spring Boot 3.2.0
- Spring Security
- Spring OAuth2 Client
- JWT (Java Web Token) with jjwt library
- JPA/H2 Database
- Lombok (for code generation)
- Jakarta EE (Servlet, Validation)

## Project Structure

```
auth-server/
├── pom.xml                              # Maven dependencies
├── src/main/java/com/auth/server/
│   ├── AuthServerApplication.java        # Main application class
│   ├── config/
│   │   ├── SecurityConfig.java           # Security configuration
│   │   ├── JwtAuthFilter.java            # JWT authentication filter
│   │   ├── JwtUtils.java                 # JWT utility functions
│   │   ├── JwtAuthEntryPoint.java        # JWT authentication entry point
│   │   ├── JwtAuthenticationFilter.java  # JWT authentication filter
│   │   └── GlobalExceptionHandler.java    # Global exception handling
│   ├── controller/
│   │   ├── AuthController.java           # Authentication endpoints
│   │   └── OAuth2Controller.java         # OAuth2 callback handling
│   ├── model/
│   │   └── User.java                     # User entity
│   ├── repository/
│   │   └── UserRepository.java           # User repository
│   ├── service/
│   │   ├── UserService.java              # User service implementation
│   │   └── UserDetailsServiceImpl.java   # User details implementation
│   └── util/
│       ├── JwtResponse.java              # JWT response DTO
│       ├── SignInRequest.java            # Sign-in request DTO
│       └── ApiError.java                 # API error response DTO
└── src/main/resources/
    └── application.properties           # Application configuration
```

## Setup Instructions

### 1. Clone and Build

```bash
git clone <repository-url>
cd auth-server
mvn clean install
```

### 2. Configure OAuth Providers

#### Google OAuth 2.0
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 Client ID for Web Application
5. Add authorized redirect URI: `http://localhost:8080/login/oauth2/code/google`

#### GitHub OAuth 2.0
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Authorization callback URL: `http://localhost:8080/login/oauth2/code/github`

#### Microsoft OAuth 2.0
1. Go to [Azure Portal](https://portal.azure.com/)
2. Create a new App Registration
3. Add web platform and redirect URI: `http://localhost:8080/login/oauth2/code/microsoft`

### 3. Configure Environment Variables

Create a `.env` file or set environment variables:

```bash
# Google OAuth 2.0
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth 2.0
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Microsoft OAuth 2.0
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
```

### 4. Run the Application

```bash
# Using Maven
mvn spring-boot:run

# Or run the JAR
java -jar target/auth-server-1.0.0.jar
```

## API Endpoints

### Authentication Endpoints

#### Sign In
```
POST /api/auth/signin
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}

Response:
{
  "token": "jwt-token-here"
}
```

#### Get Current User
```
GET /api/auth/me
Headers:
Authorization: Bearer jwt-token-here

Response:
{
  "id": 1,
  "email": "user@example.com",
  "fullName": "John Doe",
  "provider": "google",
  "imageUrl": "https://example.com/avatar.jpg",
  "emailVerified": true,
  "enabled": true,
  "authorities": ["ROLE_USER"]
}
```

#### Logout
```
POST /api/auth/logout

Response:
{
  "message": "Logout successful. Please remove token from client storage."
}
```

### OAuth2 Authentication Endpoints

#### Get Available Providers
```
GET /api/auth/providers

Response:
{
  "providers": {
    "google": {
      "name": "Google",
      "scope": "openid email profile",
      "authorizationUrl": "/oauth2/authorization/google"
    },
    "github": {
      "name": "GitHub",
      "scope": "user:email",
      "authorizationUrl": "/oauth2/authorization/github"
    },
    "microsoft": {
      "name": "Microsoft",
      "scope": "User.Read",
      "authorizationUrl": "/oauth2/authorization/microsoft"
    }
  }
}
```

#### OAuth User Info
```
GET /api/oauth2/user
Authentication: OAuth2 token from provider

Response:
{
  "status": "success",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "fullName": "John Doe",
    "provider": "google",
    "imageUrl": "https://example.com/avatar.jpg",
    "emailVerified": true
  }
}
```

### OAuth2 Login URLs

- **Google**: `http://localhost:8080/oauth2/authorization/google`
- **GitHub**: `http://localhost:8080/oauth2/authorization/github`
- **Microsoft**: `http://localhost:8080/oauth2/authorization/microsoft`

## Database Configuration

The application uses H2 in-memory database by default. You can access the H2 console at:
- URL: `http://localhost:8080/h2-console`
- JDBC URL: `jdbc:h2:mem:testdb`
- Username: `sa`
- Password: `password`

## CORS Configuration

By default, CORS is configured for:
- `http://localhost:3000` (React development)
- `http://localhost:4200` (Angular development)

You can modify this in `SecurityConfig.java`.

## JWT Configuration

Default JWT settings:
- Token expiration: 24 hours (86400000 milliseconds)
- Algorithm: HS256
- Secret: Configurable via `JWT_SECRET` environment variable

Error handling responses are standardized with proper HTTP status codes:

| Status | Error Type | Description |
|--------|------------|-------------|
| 401 Unauthorized | Authentication failed | Invalid credentials or JWT token |
| 400 Bad Request | Validation failed | Invalid request parameters |
| 500 Internal Server Error | Server error | Unexpected errors |

## Security Features

- **Stateless Authentication**: Uses JWT tokens for requestless authentication
- **OAuth 2.0 Integration**: Secure authentication with major providers
- **Role-Based Access Control**: Built-in user roles and authorities
- **CORS Protection**: Configurable cross-origin resource sharing
- **Input Validation**: Jakarta Bean Validation annotations
- **Exception Handling**: Global centralized error handling

## Production Deployment

1. **Database**: Replace H2 with PostgreSQL, MySQL, or production database
2. **JWT Secret**: Use a strong, random JWT secret in production
3. **HTTPS**: Always use HTTPS in production
4. **CORS**: Configure specific domains for production
5. **Monitoring**: Add application monitoring and logging

## Development

### Running Tests

```bash
mvn test
```

### Using H2 Console

- Start the application
- Navigate to `http://localhost:8080/h2-console`
- Use JDBC URL: `jdbc:h2:mem:testdb`
- Connect with user `sa` and password `password`

## License

This project is open source and available under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Support

For issues and questions, please open an issue in the GitHub repository.