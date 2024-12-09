using Microsoft.AspNetCore.Mvc;
using EComAPI.Services;
using EComAPI.Models;

namespace EComAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;

    public AuthController(AuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var result = await _authService.RegisterAsync(model.Email, model.Password, model.FirstName, model.LastName);
        if (!result.success)
        {
            return BadRequest(new { Message = result.message });
        }

        return Ok(new { Message = result.message, Token = result.token, RefreshToken = result.refreshToken });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var result = await _authService.LoginAsync(model.Email, model.Password);
        if (!result.success)
        {
            if (result.message == "2FA required")
            {
                return Ok(new { Require2FA = true });
            }
            return BadRequest(new { Message = result.message });
        }

        return Ok(new { Message = result.message, Token = result.token, RefreshToken = result.refreshToken });
    }

    [HttpPost("enable-2fa")]
    public async Task<IActionResult> Enable2FA([FromBody] Enable2FAModel model)
    {
        var result = await _authService.Enable2FAAsync(model.Email);
        if (!result.success)
        {
            return BadRequest(new { Message = result.message });
        }

        return Ok(new { Message = result.message });
    }

    [HttpPost("verify-2fa")]
    public async Task<IActionResult> Verify2FA([FromBody] Verify2FAModel model)
    {
        var result = await _authService.Verify2FAAsync(model.Email, model.Code);
        if (!result.success)
        {
            return BadRequest(new { Message = result.message });
        }

        return Ok(new { Message = result.message });
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel model)
    {
        var result = await _authService.ForgotPasswordAsync(model.Email);
        if (!result.success)
        {
            return BadRequest(new { Message = result.message });
        }

        return Ok(new { Message = "Password reset link has been sent to your email" });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
    {
        var result = await _authService.ResetPasswordAsync(model.Email, model.Token, model.NewPassword);
        if (!result.success)
        {
            return BadRequest(new { Message = result.message });
        }

        return Ok(new { Message = result.message });
    }
}
