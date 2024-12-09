# EComAPI

EComAPI is a .NET 8.0 Web API for an e-commerce platform with robust authentication and item management features.

## Features

- **Authentication System**
  - User Registration
  - Login with JWT
  - Two-Factor Authentication (2FA)
  - Password Reset
  - Refresh Token Mechanism

- **Item Management**
  - CRUD operations for items
  - RESTful API endpoints

## Technical Stack

- **Framework**: .NET 8.0
- **ORM**: Entity Framework Core
- **Database**: SQL Server LocalDB
- **Authentication**: ASP.NET Core Identity
- **JWT Token-based Authentication**

## Database Configuration

- **Connection String**: 
  `Server=localdb;Database=EComAPIDb;Trusted_Connection=True;MultipleActiveResultSets=true`

## Key Models

1. **ApplicationUser**
   - Extended Identity User
   - Additional fields: FirstName, LastName
   - Two-Factor Authentication support
   - Refresh Token management

2. **Item**
   - Properties: Id, Name, Description, Price, Stock

## Security Features

- Password hashing (BCrypt)
- JWT Token generation
- Two-Factor Authentication
- Secure password reset mechanism

## Packages/Dependencies

- Microsoft.AspNetCore.Authentication.JwtBearer
- Microsoft.AspNetCore.Identity.EntityFrameworkCore
- Microsoft.EntityFrameworkCore.SqlServer
- BCrypt.Net-Next
- Otp.NET
- MailKit

## Running the Application

1. Ensure you have the .NET SDK 8.0 installed.
2. Update the `appsettings.json` with your configuration.
3. Run the application using `dotnet run`.
4. Access the API documentation at `http://localhost/swagger`.

## Potential Improvements

- Implement more granular authorization
- Add comprehensive logging
- Create more detailed error responses
- Implement rate limiting
- Add more advanced two-factor authentication options
