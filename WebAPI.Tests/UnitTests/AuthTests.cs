using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using WebAPI.Data;
using WebAPI.DTOs;
using WebAPI.Exceptions;
using WebAPI.Models;
using WebAPI.Services;
using WebAPI.Tests.TestHelpers;
using Xunit;

namespace WebAPI.Tests.UnitTests;

public class AuthTests : IDisposable
{
    private readonly AppDbContext _db;
    private readonly Mock<UserManager<ApplicationUser>> _userManager;
    private readonly Mock<SignInManager<ApplicationUser>> _signInManager;
    private readonly Mock<ITokenService> _tokenService;
    private readonly Mock<IEmailSender> _emailSender;
    private readonly AuthService _sut; // system under test

    public AuthTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new AppDbContext(options);

        _userManager = IdentityMockFactory.MockUserManager();
        _signInManager = IdentityMockFactory.MockSignInManager(_userManager.Object);
        _tokenService = new Mock<ITokenService>();
        _emailSender = new Mock<IEmailSender>();

        _sut = new AuthService(
            _userManager.Object,
            _signInManager.Object,
            _tokenService.Object,
            _emailSender.Object,
            _db,
            new Mock<ILogger<AuthService>>().Object);
    }

    public void Dispose() => _db.Dispose();

    private static ApplicationUser MakeUser(bool isActive = true, string securityStamp = "stamp-1") => new()
    {
        Id = Guid.NewGuid(),
        Email = "user@test.com",
        UserName = "user@test.com",
        IsActive = isActive,
        SecurityStamp = securityStamp,
    };

    // ---------- SignupAsync ----------

    [Fact]
    public async Task SignupAsync_ValidRequest_CreatesUserAndAssignsUserRole()
    {
        var request = new SignupRequest { Email = "New@Test.com", Password = "Passw0rd1!" };

        _userManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Success);
        _userManager.Setup(m => m.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"))
            .ReturnsAsync(IdentityResult.Success);

        var result = await _sut.SignupAsync(request);

        Assert.Equal("new@test.com", result.Email); // lowercased
        _userManager.Verify(m => m.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"), Times.Once);
    }

    [Fact]
    public async Task SignupAsync_DuplicateEmail_ThrowsConflict()
    {
        var request = new SignupRequest { Email = "dup@test.com", Password = "Passw0rd1!" };
        var errors = new[] { new IdentityError { Code = "DuplicateEmail", Description = "Email taken" } };

        _userManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Failed(errors));

        await Assert.ThrowsAsync<ConflictApiException>(() => _sut.SignupAsync(request));
    }

    [Fact]
    public async Task SignupAsync_WeakPassword_ThrowsValidationWithIdentityErrors()
    {
        var request = new SignupRequest { Email = "weak@test.com", Password = "123" };
        var errors = new[] { new IdentityError { Code = "PasswordTooShort", Description = "Too short" } };

        _userManager.Setup(m => m.CreateAsync(It.IsAny<ApplicationUser>(), request.Password))
            .ReturnsAsync(IdentityResult.Failed(errors));

        var ex = await Assert.ThrowsAsync<ValidationApiException>(() => _sut.SignupAsync(request));
        Assert.Contains("Too short", ex.Errors);
    }

    // ---------- LoginAsync ----------

    [Fact]
    public async Task LoginAsync_ValidCredentials_ReturnsUserAndTokensAndUpdatesLastLogin()
    {
        var user = MakeUser();
        _userManager.Setup(m => m.FindByEmailAsync("user@test.com")).ReturnsAsync(user);
        _signInManager.Setup(m => m.CheckPasswordSignInAsync(user, "correct", true))
            .ReturnsAsync(SignInResult.Success);
        _tokenService.Setup(t => t.CreateAccessToken(user.Id)).Returns("access-jwt");
        _tokenService.Setup(t => t.GenerateRefreshToken()).Returns(("raw", "hash", DateTime.UtcNow.AddDays(30)));
        _userManager.Setup(m => m.UpdateAsync(user)).ReturnsAsync(IdentityResult.Success);

        var (returnedUser, accessToken, rawRefresh) = await _sut.LoginAsync(
            new LoginRequest { Email = "user@test.com", Password = "correct" });

        Assert.Equal("access-jwt", accessToken);
        Assert.Equal("raw", rawRefresh);
        Assert.NotNull(user.LastLogin);
        Assert.Single(_db.RefreshTokens);
    }

    [Fact]
    public async Task LoginAsync_NoSuchUser_ThrowsUnauthorized_GenericMessage()
    {
        _userManager.Setup(m => m.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync((ApplicationUser?)null);

        var ex = await Assert.ThrowsAsync<UnauthorizedApiException>(() =>
            _sut.LoginAsync(new LoginRequest { Email = "nobody@test.com", Password = "x" }));

        // Message must not reveal whether the account exists.
        Assert.Equal("Invalid email or password", ex.Message);
    }

    [Fact]
    public async Task LoginAsync_WrongPassword_ThrowsUnauthorized_SameGenericMessageAsNoSuchUser()
    {
        var user = MakeUser();
        _userManager.Setup(m => m.FindByEmailAsync(user.Email!)).ReturnsAsync(user);
        _signInManager.Setup(m => m.CheckPasswordSignInAsync(user, "wrong", true))
            .ReturnsAsync(SignInResult.Failed);

        var ex = await Assert.ThrowsAsync<UnauthorizedApiException>(() =>
            _sut.LoginAsync(new LoginRequest { Email = user.Email!, Password = "wrong" }));

        Assert.Equal("Invalid email or password", ex.Message);
    }

    [Fact]
    public async Task LoginAsync_LockedOutAccount_Throws423Locked()
    {
        var user = MakeUser();
        _userManager.Setup(m => m.FindByEmailAsync(user.Email!)).ReturnsAsync(user);
        _signInManager.Setup(m => m.CheckPasswordSignInAsync(user, It.IsAny<string>(), true))
            .ReturnsAsync(SignInResult.LockedOut);

        var ex = await Assert.ThrowsAsync<LockedApiException>(() =>
            _sut.LoginAsync(new LoginRequest { Email = user.Email!, Password = "x" }));

        Assert.Equal(423, ex.StatusCode);
    }

    [Fact]
    public async Task LoginAsync_DisabledAccount_ThrowsForbidden()
    {
        var user = MakeUser(isActive: false);
        _userManager.Setup(m => m.FindByEmailAsync(user.Email!)).ReturnsAsync(user);
        _signInManager.Setup(m => m.CheckPasswordSignInAsync(user, "correct", true))
            .ReturnsAsync(SignInResult.Success);

        await Assert.ThrowsAsync<ForbiddenApiException>(() =>
            _sut.LoginAsync(new LoginRequest { Email = user.Email!, Password = "correct" }));
    }

    // ---------- RefreshAsync ----------

    [Fact]
    public async Task RefreshAsync_ValidToken_RotatesAndIssuesNewTokens()
    {
        var user = MakeUser();
        var oldToken = new RefreshToken
        {
            UserId = user.Id, User = user, TokenHash = "hash-old",
            ExpiresAt = DateTime.UtcNow.AddDays(1), SecurityStamp = user.SecurityStamp!,
        };
        _db.RefreshTokens.Add(oldToken);
        await _db.SaveChangesAsync();

        _tokenService.Setup(t => t.HashRefreshToken("raw-old")).Returns("hash-old");
        _tokenService.Setup(t => t.CreateAccessToken(user.Id)).Returns("new-access");
        _tokenService.Setup(t => t.GenerateRefreshToken()).Returns(("new-raw", "hash-new", DateTime.UtcNow.AddDays(30)));
        _userManager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false);

        var (_, accessToken, newRaw) = await _sut.RefreshAsync("raw-old");

        Assert.Equal("new-access", accessToken);
        Assert.Equal("new-raw", newRaw);
        Assert.True(oldToken.IsRevoked); // old row revoked, not deleted
        Assert.Equal(2, _db.RefreshTokens.Count()); // old (revoked) + new
    }

    [Fact]
    public async Task RefreshAsync_TokenNotFound_ThrowsUnauthorized()
    {
        _tokenService.Setup(t => t.HashRefreshToken(It.IsAny<string>())).Returns("no-match");

        await Assert.ThrowsAsync<UnauthorizedApiException>(() => _sut.RefreshAsync("bogus"));
    }

    [Fact]
    public async Task RefreshAsync_ExpiredToken_ThrowsUnauthorized()
    {
        var user = MakeUser();
        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id, User = user, TokenHash = "hash-expired",
            ExpiresAt = DateTime.UtcNow.AddDays(-1), SecurityStamp = user.SecurityStamp!,
        });
        await _db.SaveChangesAsync();
        _tokenService.Setup(t => t.HashRefreshToken("raw")).Returns("hash-expired");

        await Assert.ThrowsAsync<UnauthorizedApiException>(() => _sut.RefreshAsync("raw"));
    }

    [Fact]
    public async Task RefreshAsync_RevokedTokenReused_RevokesAllActiveSessionsForUser()
    {
        var user = MakeUser();
        var reused = new RefreshToken
        {
            UserId = user.Id, User = user, TokenHash = "hash-revoked", IsRevoked = true,
            ExpiresAt = DateTime.UtcNow.AddDays(1), SecurityStamp = user.SecurityStamp!,
        };
        var otherActive = new RefreshToken
        {
            UserId = user.Id, TokenHash = "hash-other-active",
            ExpiresAt = DateTime.UtcNow.AddDays(1), SecurityStamp = user.SecurityStamp!,
        };
        _db.RefreshTokens.AddRange(reused, otherActive);
        await _db.SaveChangesAsync();
        _tokenService.Setup(t => t.HashRefreshToken("raw")).Returns("hash-revoked");

        await Assert.ThrowsAsync<UnauthorizedApiException>(() => _sut.RefreshAsync("raw"));

        Assert.True(otherActive.IsRevoked); // the OTHER session, not just the reused one
    }

    [Fact]
    public async Task RefreshAsync_SecurityStampMismatch_RevokesAllSessions_AfterPasswordChange()
    {
        var user = MakeUser(securityStamp: "new-stamp");
        var staleToken = new RefreshToken
        {
            UserId = user.Id, User = user, TokenHash = "hash-stale",
            ExpiresAt = DateTime.UtcNow.AddDays(1), SecurityStamp = "old-stamp-before-password-change",
        };
        _db.RefreshTokens.Add(staleToken);
        await _db.SaveChangesAsync();
        _tokenService.Setup(t => t.HashRefreshToken("raw")).Returns("hash-stale");
        _userManager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false);

        await Assert.ThrowsAsync<UnauthorizedApiException>(() => _sut.RefreshAsync("raw"));

        Assert.True(staleToken.IsRevoked);
    }

    [Fact]
    public async Task RefreshAsync_LockedOutUser_ThrowsUnauthorized()
    {
        var user = MakeUser();
        var tokenRow = new RefreshToken
        {
            UserId = user.Id,
            User = user,
            TokenHash = "hash-locked",
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            SecurityStamp = user.SecurityStamp!,
        };

        _db.RefreshTokens.Add(tokenRow);
        await _db.SaveChangesAsync();

        _tokenService
            .Setup(t => t.HashRefreshToken("raw-locked"))
            .Returns("hash-locked");

        _userManager
            .Setup(m => m.IsLockedOutAsync(user))
            .ReturnsAsync(true);

        var exception = await Assert.ThrowsAsync<UnauthorizedApiException>(
            () => _sut.RefreshAsync("raw-locked"));

        Assert.Equal(
            "Account is currently locked",
            exception.Message);
    }

    // ---------- LogoutAsync ----------

    [Fact]
    public async Task LogoutAsync_ValidToken_RevokesIt()
    {
        var row = new RefreshToken
        {
            UserId = Guid.NewGuid(), TokenHash = "hash", ExpiresAt = DateTime.UtcNow.AddDays(1), SecurityStamp = "s",
        };
        _db.RefreshTokens.Add(row);
        await _db.SaveChangesAsync();
        _tokenService.Setup(t => t.HashRefreshToken("raw")).Returns("hash");

        await _sut.LogoutAsync("raw");

        Assert.True(row.IsRevoked);
    }

    [Fact]
    public async Task LogoutAsync_NullToken_DoesNotThrow()
    {
        await _sut.LogoutAsync(null); // should complete silently, no exception
    }

    [Fact]
    public async Task LogoutAsync_UnrecognizedToken_DoesNotThrow()
    {
        _tokenService.Setup(t => t.HashRefreshToken(It.IsAny<string>())).Returns("no-match");
        await _sut.LogoutAsync("bogus"); // no matching row - should no-op, not throw
    }

    // ---------- ForgotPasswordAsync ----------

    [Fact]
    public async Task ForgotPasswordAsync_ExistingUser_SendsEmail()
    {
        var user = MakeUser();
        _userManager.Setup(m => m.FindByEmailAsync(user.Email!)).ReturnsAsync(user);
        _userManager.Setup(m => m.GeneratePasswordResetTokenAsync(user)).ReturnsAsync("reset-token");

        await _sut.ForgotPasswordAsync(user.Email!, "https://app/reset?email={email}&token={token}");

        _emailSender.Verify(e => e.SendPasswordResetAsync(user.Email!, It.IsAny<string>()), Times.Once);
    }

    [Fact]
    public async Task ForgotPasswordAsync_NonexistentUser_DoesNotThrowOrSendEmail_NoEnumeration()
    {
        _userManager.Setup(m => m.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync((ApplicationUser?)null);

        await _sut.ForgotPasswordAsync("nobody@test.com", "https://app/reset?email={email}&token={token}");

        _emailSender.Verify(e => e.SendPasswordResetAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    // ---------- ResetPasswordAsync ----------

    [Fact]
    public async Task ResetPasswordAsync_ValidTokenAndUser_Succeeds()
    {
        var user = MakeUser();
        var request = new ResetPasswordRequest { Email = user.Email!, Token = "tok", NewPassword = "NewPass1!" };
        _userManager.Setup(m => m.FindByEmailAsync(user.Email!)).ReturnsAsync(user);
        _userManager.Setup(m => m.ResetPasswordAsync(user, "tok", "NewPass1!")).ReturnsAsync(IdentityResult.Success);

        await _sut.ResetPasswordAsync(request); // should not throw
    }

    [Fact]
    public async Task ResetPasswordAsync_NonexistentUser_ThrowsValidation_NoEnumeration()
    {
        _userManager.Setup(m => m.FindByEmailAsync(It.IsAny<string>())).ReturnsAsync((ApplicationUser?)null);
        var request = new ResetPasswordRequest { Email = "nobody@test.com", Token = "tok", NewPassword = "NewPass1!" };

        await Assert.ThrowsAsync<ValidationApiException>(() => _sut.ResetPasswordAsync(request));
    }

    [Fact]
    public async Task ResetPasswordAsync_InvalidToken_ThrowsValidation()
    {
        var user = MakeUser();
        var request = new ResetPasswordRequest { Email = user.Email!, Token = "bad-token", NewPassword = "NewPass1!" };
        _userManager.Setup(m => m.FindByEmailAsync(user.Email!)).ReturnsAsync(user);
        _userManager.Setup(m => m.ResetPasswordAsync(user, "bad-token", "NewPass1!"))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Invalid token" }));

        await Assert.ThrowsAsync<ValidationApiException>(() => _sut.ResetPasswordAsync(request));
    }

    // ---------- GetUserRoleAsync ----------

    [Fact]
    public async Task GetUserRoleAsync_ReturnsFirstAssignedRole()
    {
        var user = MakeUser();
        _userManager.Setup(m => m.GetRolesAsync(user)).ReturnsAsync(new List<string> { "Admin" });

        var role = await _sut.GetUserRoleAsync(user);

        Assert.Equal("Admin", role);
    }

    [Fact]
    public async Task GetUserRoleAsync_NoRoles_DefaultsToUser()
    {
        var user = MakeUser();
        _userManager.Setup(m => m.GetRolesAsync(user)).ReturnsAsync(new List<string>());

        var role = await _sut.GetUserRoleAsync(user);

        Assert.Equal("User", role);
    }
}