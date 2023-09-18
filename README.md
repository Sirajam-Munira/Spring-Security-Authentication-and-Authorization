# Spring Security Project with User Authentication and Authorization

This Spring Boot project serves as a practical simple example of implementing robust security features using Spring Security and JWT (JSON Web Tokens) for authentication. 
It includes custom authentication and authorization filters, role-based access control, password encryption and error handling. The project provides a set of RESTful 
endpoints for user registration, authentication, role-based authorization and sample "Hello" endpoints demonstrating essential security concepts in a Spring Boot application.


## Technologies

**Language:** Java

**Framework:** Spring Boot

**Security:** Spring Security

**Authentication:** JWT (JSON Web Tokens)

**Database:** MySQL


## Project Details

**Authorization Roles:** "user" and "admin"

**Session Management:** Stateless

**Authentication Filter:** Custom authentication filter for user login

**Authorization Filter:** Custom authorization filter for JWT token validation

**Dependency Injection:** Spring IoC

**Password Encryption:** BCryptPasswordEncoder

**Repository:** JPA-based UserRepository for user data

**Error Handling:** Exception handling for user-friendly error responses

**Logging:** SLF4J for logging

**JSON Serialization/Deserialization:** Jackson ObjectMapper

**RESTful Endpoints:** Registration, Authentication, User-specific, Admin-specific, Sample "Hello" endpoints

**Token Generation:** JWTUtils for token generation and validation
