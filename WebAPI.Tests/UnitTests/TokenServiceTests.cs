using Microsoft.Extensions.Configuration;
using WebAPI.Services;
using Xunit;

namespace WebAPI.Tests.UnitTests;

public class TokenServiceTests
{
    private static TokenService MakeService(string secretKey = "test-secret-key-at-least-32-bytes-long!!")
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SecretKey"] = secretKey,
                ["Jwt:AccessTokenExpirySeconds"] = "900",
                ["Jwt:RefreshTokenExpiryDays"] = "30",
            })
            .Build();
        return new TokenService(config);
    }

    [Fact]
    public void Constructor_MissingSecretKey_Throws()
    {
        var config = new ConfigurationBuilder().Build(); // no Jwt:SecretKey at all

        Assert.Throws<InvalidOperationException>(() => new TokenService(config));
    }

    [Fact]
    public void CreateAccessToken_ProducesTokenContainingCorrectSubClaim()
    {
        var service = MakeService();
        var userId = Guid.NewGuid();

        var token = service.CreateAccessToken(userId);
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var parsed = handler.ReadJwtToken(token);

        Assert.Equal(userId.ToString(), parsed.Subject);
        Assert.True(parsed.ValidTo > DateTime.UtcNow);
    }

    [Fact]
    public void GenerateRefreshToken_ProducesUniqueTokensEachCall()
    {
        var service = MakeService();

        var (raw1, hash1, _) = service.GenerateRefreshToken();
        var (raw2, hash2, _) = service.GenerateRefreshToken();

        Assert.NotEqual(raw1, raw2);
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void GenerateRefreshToken_ReturnedHashMatchesHashRefreshTokenOfRawValue()
    {
        var service = MakeService();

        var (raw, hash, _) = service.GenerateRefreshToken();

        Assert.Equal(hash, service.HashRefreshToken(raw));
    }

    [Fact]
    public void HashRefreshToken_SameInput_AlwaysProducesSameHash()
    {
        var service = MakeService();

        var hash1 = service.HashRefreshToken("some-raw-token");
        var hash2 = service.HashRefreshToken("some-raw-token");

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void HashRefreshToken_DifferentInput_ProducesDifferentHash()
    {
        var service = MakeService();

        Assert.NotEqual(service.HashRefreshToken("a"), service.HashRefreshToken("b"));
    }
    [Fact]
    public void Constructor_MissingAccessTokenExpiry_UsesDefault()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SecretKey"] =
                    "test-secret-key-at-least-32-characters-long-for-hmac",
                ["Jwt:RefreshTokenExpiryDays"] = "30"
            })
            .Build();

        var tokenService = new TokenService(configuration);

        var token = tokenService.CreateAccessToken(Guid.NewGuid());

        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public void Constructor_MissingRefreshTokenExpiry_UsesDefault()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SecretKey"] =
                    "test-secret-key-at-least-32-characters-long-for-hmac",
                ["Jwt:AccessTokenExpirySeconds"] = "900"
            })
            .Build();

        var tokenService = new TokenService(configuration);

        var result = tokenService.GenerateRefreshToken();

        Assert.False(string.IsNullOrWhiteSpace(result.rawToken));
        Assert.False(string.IsNullOrWhiteSpace(result.tokenHash));
        Assert.True(result.expiresAt > DateTime.UtcNow);
    }
}