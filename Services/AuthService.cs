using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using EComAPI.Models;
using OtpNet;

namespace EComAPI.Services;

public class AuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;

    public AuthService(UserManager<ApplicationUser> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    public async Task<(bool success, string message, string? token, string? refreshToken)> RegisterAsync(string email, string password, string firstName, string lastName)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            return (false, "User already exists", null, null);
        }

        user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = firstName,
            LastName = lastName
        };

        var result = await _userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            return (false, string.Join(", ", result.Errors.Select(e => e.Description)), null, null);
        }

        var token = GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _userManager.UpdateAsync(user);

        return (true, "Registration successful", token, refreshToken);
    }

    public async Task<(bool success, string message, string? token, string? refreshToken)> LoginAsync(string email, string password)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return (false, "Invalid credentials", null, null);
        }

        var isPasswordValid = await _userManager.CheckPasswordAsync(user, password);
        if (!isPasswordValid)
        {
            return (false, "Invalid credentials", null, null);
        }

        if (user.TwoFactorEnabled)
        {
            return (false, "2FA required", null, null);
        }

        var token = GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
        await _userManager.UpdateAsync(user);

        return (true, "Login successful", token, refreshToken);
    }

    public async Task<(bool success, string message)> Enable2FAAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return (false, "User not found");
        }

        if (user.TwoFactorEnabled)
        {
            return (false, "2FA is already enabled");
        }

        var key = KeyGeneration.GenerateRandomKey(20);
        user.TwoFactorSecretKey = Convert.ToBase64String(key);
        user.TwoFactorEnabled = true;
        
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return (false, "Failed to enable 2FA");
        }

        return (true, "2FA enabled successfully");
    }

    public async Task<(bool success, string message)> Verify2FAAsync(string email, string code)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || !user.TwoFactorEnabled || string.IsNullOrEmpty(user.TwoFactorSecretKey))
        {
            return (false, "Invalid request");
        }

        var key = Convert.FromBase64String(user.TwoFactorSecretKey ?? string.Empty);
        var totp = new Totp(key);
        
        var isValid = totp.VerifyTotp(code, out long timeStepMatched);
        if (!isValid)
        {
            return (false, "Invalid code");
        }

        return (true, "Code verified successfully");
    }

    public async Task<(bool success, string message)> ForgotPasswordAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return (false, "User not found");
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        // Here you would typically send an email with the reset token
        // For demo purposes, we'll just return the token
        return (true, token);
    }

    public async Task<(bool success, string message)> ResetPasswordAsync(string email, string token, string newPassword)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return (false, "User not found");
        }

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (!result.Succeeded)
        {
            return (false, string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        return (true, "Password reset successful");
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id ?? string.Empty),
            new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"] ?? "default_secret"));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}
