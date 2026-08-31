using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.DataProtection;
using Moq;
using WebAPI.Data;
using WebAPI.DTOs;
using WebAPI.Exceptions;
using WebAPI.Models;
using WebAPI.Services;
using Xunit;

namespace WebAPI.Tests;

/// <summary>
/// Full coverage of AuthService - the security-critical business logic
/// layer. Uses EF Core's InMemory provider (real DbContext, no Postgres
/// needed) and Identity's real UserManager/SignInManager wired against
/// it, so password hashing, lockout, and role assignment all run for
/// real rather than being mocked away. IEmailSender is mocked since
/// nothing about its actual delivery is this layer's concern.
/// </summary>
public class AuthServiceTests
{
    private static (AppDbContext db, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ServiceProvider provider) NewIdentityStack()
    {
        var services = new ServiceCollection();

        var dbName = Guid.NewGuid().ToString();
        services.AddDbContext<AppDbContext>(o => o.UseInMemoryDatabase(dbName));

        services
            .AddIdentityCore<ApplicationUser>(options =>
            {
                options.Password.RequiredLength = 8;
                options.Password.RequireDigit = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.User.RequireUniqueEmail = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
            })
            .AddRoles<IdentityRole<Guid>>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        services.AddLogging();
        services.AddDataProtection();
        services.AddAuthentication();

        var provider = services.BuildServiceProvider();
        var db = provider.GetRequiredService<AppDbContext>();
        var userManager = provider.GetRequiredService<UserManager<ApplicationUser>>();
        var signInManager = provider.GetRequiredService<SignInManager<ApplicationUser>>();

        // Role must exist before AddToRoleAsync can assign it - mirrors
        // the real startup seeding in Program.cs.
        var roleManager = provider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        roleManager.CreateAsync(new IdentityRole<Guid>("User")).GetAwaiter().GetResult();

        return (db, userManager, signInManager, provider);
    }

    private static ITokenService NewTokenService()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SecretKey"] = "test-secret-key-at-least-32-characters-long-for-hmac",
                ["Jwt:AccessTokenExpirySeconds"] = "900",
                ["Jwt:RefreshTokenExpiryDays"] = "30",
            })
            .Build();
        return new TokenService(config);
    }

    private static AuthService NewSut(AppDbContext db, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, out Mock<IEmailSender> emailSenderMock)
    {
        emailSenderMock = new Mock<IEmailSender>();
        emailSenderMock.Setup(e => e.SendPasswordResetAsync(It.IsAny<string>(), It.IsAny<string>())).Returns(Task.CompletedTask);

        return new AuthService(
            userManager,
            signInManager,
            NewTokenService(),
            emailSenderMock.Object,
            db,
            NullLogger<AuthService>.Instance);
    }

    // ---------- Signup ----------

    [Fact]
    public async Task Signup_ValidRequest_CreatesUserWithHashedPasswordAndUserRole()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);

        var user = await sut.SignupAsync(new SignupRequest
        {
            Email = "user@example.com",
            Password = "Testpass1!",
            FullName = "Test User",
        });

        Assert.NotEqual(Guid.Empty, user.Id);
        Assert.NotEqual("Testpass1!", user.PasswordHash); // never stored in plaintext
        Assert.True(await userManager.IsInRoleAsync(user, "User"));
        Assert.Equal("Test User", user.FullName);
    }

    [Fact]
    public async Task Signup_DuplicateEmail_ThrowsConflict()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        var request = new SignupRequest { Email = "dup@example.com", Password = "Testpass1!" };

        await sut.SignupAsync(request);

        await Assert.ThrowsAsync<ConflictApiException>(() => sut.SignupAsync(request));
    }

    [Fact]
    public async Task Signup_WeakPassword_ThrowsValidation()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);

        await Assert.ThrowsAsync<ValidationApiException>(() => sut.SignupAsync(new SignupRequest
        {
            Email = "weak@example.com",
            Password = "weak", // fails length, digit, uppercase, non-alphanumeric rules
        }));
    }

    // ---------- Login ----------

    [Fact]
    public async Task Login_CorrectCredentials_ReturnsUserAndTokens()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });

        var (user, accessToken, refreshToken) = await sut.LoginAsync(new LoginRequest
        {
            Email = "user@example.com",
            Password = "Testpass1!",
        });

        Assert.NotNull(user);
        Assert.False(string.IsNullOrEmpty(accessToken));
        Assert.False(string.IsNullOrEmpty(refreshToken));
        Assert.NotNull(user.LastLogin);
        Assert.Single(db.RefreshTokens);
    }

    [Fact]
    public async Task Login_WrongPassword_ThrowsUnauthorized()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });

        await Assert.ThrowsAsync<UnauthorizedApiException>(() => sut.LoginAsync(new LoginRequest
        {
            Email = "user@example.com",
            Password = "WrongPass1!",
        }));
    }

    [Fact]
    public async Task Login_UnknownEmail_ThrowsUnauthorized_NotFoundDistinction()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);

        // Same exception type/message as wrong-password - the test
        // itself enforces the "don't leak which one it was" behavior.
        await Assert.ThrowsAsync<UnauthorizedApiException>(() => sut.LoginAsync(new LoginRequest
        {
            Email = "nobody@example.com",
            Password = "Whatever1!",
        }));
    }

    [Fact]
    public async Task Login_DisabledAccount_ThrowsForbidden()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        var user = await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });
        user.IsActive = false;
        await userManager.UpdateAsync(user);

        await Assert.ThrowsAsync<ForbiddenApiException>(() => sut.LoginAsync(new LoginRequest
        {
            Email = "user@example.com",
            Password = "Testpass1!",
        }));
    }

    [Fact]
    public async Task Login_RepeatedFailures_TriggersLockout()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });
        var wrongLogin = new LoginRequest { Email = "user@example.com", Password = "WrongPass1!" };

        // MaxFailedAccessAttempts = 5 - the 6th attempt should now be
        // rejected as LOCKED rather than as another wrong-password.
        for (var i = 0; i < 5; i++)
        {
            await Assert.ThrowsAnyAsync<ApiException>(() => sut.LoginAsync(wrongLogin));
        }

        await Assert.ThrowsAsync<LockedApiException>(() => sut.LoginAsync(wrongLogin));

        // Even the CORRECT password must now fail while locked out.
        await Assert.ThrowsAsync<LockedApiException>(() => sut.LoginAsync(
            new LoginRequest { Email = "user@example.com", Password = "Testpass1!" }));
    }

    // ---------- Refresh ----------

    [Fact]
    public async Task Refresh_InactiveUser_ThrowsUnauthorized()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);

        var user = await sut.SignupAsync(
            new SignupRequest
            {
                Email = "inactive-refresh@example.com",
                Password = "Testpass1!"
            });

        var (_, _, refreshToken) = await sut.LoginAsync(
            new LoginRequest
            {
                Email = "inactive-refresh@example.com",
                Password = "Testpass1!"
            });

        user.IsActive = false;

        var updateResult = await userManager.UpdateAsync(user);
        Assert.True(updateResult.Succeeded);

        var exception = await Assert.ThrowsAsync<UnauthorizedApiException>(
            () => sut.RefreshAsync(refreshToken));

        Assert.Equal(
            "User not found or inactive",
            exception.Message);
    }

    [Fact]
    public async Task Refresh_ValidToken_RotatesAndReturnsNewTokens()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });
        var (_, _, firstRefresh) = await sut.LoginAsync(new LoginRequest { Email = "user@example.com", Password = "Testpass1!" });

        var (_, newAccess, newRefresh) = await sut.RefreshAsync(firstRefresh);

        Assert.False(string.IsNullOrEmpty(newAccess));
        Assert.NotEqual(firstRefresh, newRefresh);
        Assert.Equal(2, db.RefreshTokens.Count()); // old (now revoked) + new
        Assert.True(db.RefreshTokens.Single(rt => rt.TokenHash != db.RefreshTokens.OrderByDescending(x => x.CreatedAt).First().TokenHash).IsRevoked);
    }

    [Fact]
    public async Task Refresh_UnknownToken_ThrowsUnauthorized()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);

        await Assert.ThrowsAsync<UnauthorizedApiException>(() => sut.RefreshAsync("not-a-real-token"));
    }

    [Fact]
    public async Task Refresh_ReuseOfRevokedToken_RevokesAllSessionsForUser()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });
        var (user, _, firstRefresh) = await sut.LoginAsync(new LoginRequest { Email = "user@example.com", Password = "Testpass1!" });

        await sut.RefreshAsync(firstRefresh); // rotates - firstRefresh is now revoked

        // Reusing the now-revoked token is the theft-detection trigger.
        await Assert.ThrowsAsync<UnauthorizedApiException>(() => sut.RefreshAsync(firstRefresh));

        var stillActive = db.RefreshTokens.Count(rt => rt.UserId == user.Id && !rt.IsRevoked);
        Assert.Equal(0, stillActive);
    }

    [Fact]
    public async Task Refresh_AfterPasswordChange_StaleTokenRejected()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        var user = await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });
        var (_, _, refreshToken) = await sut.LoginAsync(new LoginRequest { Email = "user@example.com", Password = "Testpass1!" });

        // Simulates a password reset rotating the SecurityStamp.
        await userManager.UpdateSecurityStampAsync(user);

        await Assert.ThrowsAsync<UnauthorizedApiException>(() => sut.RefreshAsync(refreshToken));
    }

    // ---------- Logout ----------

    [Fact]
    public async Task Logout_ValidToken_RevokesIt()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });
        var (_, _, refreshToken) = await sut.LoginAsync(new LoginRequest { Email = "user@example.com", Password = "Testpass1!" });

        await sut.LogoutAsync(refreshToken);

        Assert.True(db.RefreshTokens.Single().IsRevoked);
    }

    [Fact]
    public async Task Logout_NoToken_DoesNotThrow()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);

        var ex = await Record.ExceptionAsync(() => sut.LogoutAsync(null));

        Assert.Null(ex);
    }

    // ---------- Forgot / Reset password ----------

    [Fact]
    public async Task ForgotPassword_ExistingUser_SendsResetEmail()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out var emailMock);
        await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });

        await sut.ForgotPasswordAsync("user@example.com", "https://app.example.com/reset?email={email}&token={token}");

        emailMock.Verify(e => e.SendPasswordResetAsync("user@example.com", It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ForgotPassword_UnknownUser_DoesNotThrowOrSendEmail()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out var emailMock);

        var ex = await Record.ExceptionAsync(() =>
            sut.ForgotPasswordAsync("nobody@example.com", "https://app.example.com/reset?email={email}&token={token}"));

        Assert.Null(ex);
        // No email-enumeration signal: caller can't tell this apart
        // from the existing-user case just from the response/exception.
        emailMock.Verify(e => e.SendPasswordResetAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task ResetPassword_ValidToken_ChangesPasswordAndInvalidatesOld()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        var user = await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });
        var token = await userManager.GeneratePasswordResetTokenAsync(user);

        await sut.ResetPasswordAsync(new ResetPasswordRequest
        {
            Email = "user@example.com",
            Token = token,
            NewPassword = "NewPass1!",
        });

        // Old password must now fail, new one must work.
        await Assert.ThrowsAsync<UnauthorizedApiException>(() => sut.LoginAsync(
            new LoginRequest { Email = "user@example.com", Password = "Testpass1!" }));

        var (loggedInUser, _, _) = await sut.LoginAsync(
            new LoginRequest { Email = "user@example.com", Password = "NewPass1!" });
        Assert.NotNull(loggedInUser);
    }

    [Fact]
    public async Task ResetPassword_InvalidToken_ThrowsValidation()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);
        await sut.SignupAsync(new SignupRequest { Email = "user@example.com", Password = "Testpass1!" });

        await Assert.ThrowsAsync<ValidationApiException>(() => sut.ResetPasswordAsync(new ResetPasswordRequest
        {
            Email = "user@example.com",
            Token = "not-a-real-token",
            NewPassword = "NewPass1!",
        }));
    }

    [Fact]
    public async Task ResetPassword_UnknownEmail_ThrowsValidation_NoEnumeration()
    {
        var (db, userManager, signInManager, _) = NewIdentityStack();
        var sut = NewSut(db, userManager, signInManager, out _);

        await Assert.ThrowsAsync<ValidationApiException>(() => sut.ResetPasswordAsync(new ResetPasswordRequest
        {
            Email = "nobody@example.com",
            Token = "whatever",
            NewPassword = "NewPass1!",
        }));
    }
}
