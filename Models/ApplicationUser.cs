using Microsoft.AspNetCore.Identity;

namespace EComAPI.Models;

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
    public new bool TwoFactorEnabled { get; set; }
    public string? TwoFactorSecretKey { get; set; }
}
