using WebAPI.Data;
using WebAPI.DTOs;
using WebAPI.Exceptions;
using WebAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace WebAPI.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly AppDbContext _db;
    private readonly ILogger<AuthService> _logger;
    private readonly IEmailSender _emailSender;

    public AuthService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    ITokenService tokenService,
    IEmailSender emailSender,
    AppDbContext db,
    ILogger<AuthService> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _emailSender = emailSender;
        _db = db;
        _logger = logger;
    }

    public async Task<ApplicationUser> SignupAsync(SignupRequest request)
    {
        var email = request.Email.Trim().ToLowerInvariant();

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FullName = request.FullName,
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            if (result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail"))
            {
                _logger.LogInformation("Signup rejected - duplicate email");
                throw new ConflictApiException("An account with this email already exists.");
            }

            _logger.LogInformation("Signup rejected by Identity validation: {Errors}",
                string.Join(", ", result.Errors.Select(e => e.Code)));
            throw new ValidationApiException(result.Errors.Select(e => e.Description));
        }

        await _userManager.AddToRoleAsync(user, "User");

        _logger.LogInformation("User {UserId} signed up", user.Id);
        return user;
    }

    public async Task<string> GetUserRoleAsync(ApplicationUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);
        return roles.FirstOrDefault() ?? "User";
    }

    public async Task<(ApplicationUser user, string accessToken, string rawRefreshToken)> LoginAsync(LoginRequest request)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var user = await _userManager.FindByEmailAsync(email);

        if (user is null)
        {
            _logger.LogInformation("Login failed - no account for this email");
            throw new UnauthorizedApiException("Invalid email or password");
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (result.IsLockedOut)
        {
            _logger.LogWarning("Login blocked - user {UserId} is locked out", user.Id);
            throw new LockedApiException("Account temporarily locked due to repeated failed attempts. Try again later.");
        }

        if (!result.Succeeded)
        {
            _logger.LogInformation("Login failed - bad password for user {UserId}", user.Id);
            throw new UnauthorizedApiException("Invalid email or password");
        }

        if (!user.IsActive)
        {
            _logger.LogInformation("Login blocked - user {UserId} is disabled", user.Id);
            throw new ForbiddenApiException("Account is disabled");
        }

        var accessToken = _tokenService.CreateAccessToken(user.Id);
        var (rawRefresh, refreshHash, expiresAt) = _tokenService.GenerateRefreshToken();

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshHash,
            ExpiresAt = expiresAt,
        });

        user.LastLogin = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await _db.SaveChangesAsync();

        _logger.LogInformation("User {UserId} logged in", user.Id);
        return (user, accessToken, rawRefresh);
    }

    public async Task<(ApplicationUser user, string accessToken, string rawRefreshToken)> RefreshAsync(string rawRefreshToken)
    {
        var tokenHash = _tokenService.HashRefreshToken(rawRefreshToken);
        var tokenRow = await _db.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);

        if (tokenRow is null || tokenRow.IsRevoked || tokenRow.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogInformation("Refresh rejected - token invalid, revoked, or expired");
            throw new UnauthorizedApiException("Refresh token invalid or expired");
        }

        var user = tokenRow.User;

        if (!user.IsActive)
        {
            _logger.LogInformation("Refresh rejected - user {UserId} inactive", user.Id);
            throw new UnauthorizedApiException("User not found or inactive");
        }


        if (await _userManager.IsLockedOutAsync(user))
        {
            _logger.LogWarning("Refresh rejected - user {UserId} is locked out", user.Id);
            throw new UnauthorizedApiException("Account is currently locked");
        }

        tokenRow.IsRevoked = true;

        var accessToken = _tokenService.CreateAccessToken(user.Id);
        var (newRawRefresh, newRefreshHash, newExpiresAt) = _tokenService.GenerateRefreshToken();

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = newRefreshHash,
            ExpiresAt = newExpiresAt,
        });
        await _db.SaveChangesAsync();

        return (user, accessToken, newRawRefresh);
    }
    public async Task LogoutAsync(string? rawRefreshToken)
    {

        if (string.IsNullOrEmpty(rawRefreshToken)) return;

        var tokenHash = _tokenService.HashRefreshToken(rawRefreshToken);
        var tokenRow = await _db.RefreshTokens.FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);
        if (tokenRow is not null)
        {
            tokenRow.IsRevoked = true;
            await _db.SaveChangesAsync();
        }
    }

    public async Task ForgotPasswordAsync(string email, string linkTemplate)
    {
        var user = await _userManager.FindByEmailAsync(email.Trim().ToLowerInvariant());
        
        if (user is null) return;

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        var link = linkTemplate
            .Replace("{email}", Uri.EscapeDataString(user.Email!))
            .Replace("{token}", Uri.EscapeDataString(token));

        await _emailSender.SendPasswordResetAsync(user.Email!, link);
        _logger.LogInformation("Sent password reset email to user {UserId} where token is {Token}", user.Id, token);
    }

    public async Task ResetPasswordAsync(ResetPasswordRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email.Trim().ToLowerInvariant());
        if (user is null)
            throw new ValidationApiException(new[] { "Invalid or expired reset link" });

        var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
        if (!result.Succeeded)
            throw new ValidationApiException(result.Errors.Select(e => e.Description));

        _logger.LogInformation("User {UserId} reset their password", user.Id);
    }

}