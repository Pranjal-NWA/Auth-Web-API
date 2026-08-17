using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace WebAPI.Services;

public class TokenService : ITokenService
{
    private readonly string _secretKey;
    private readonly double _accessTokenExpirySeconds;
    private readonly int _refreshTokenExpiryDays;

    public TokenService(IConfiguration config)
    {
        _secretKey = config["Jwt:SecretKey"]
            ?? throw new InvalidOperationException("Jwt:SecretKey is not configured");
        _accessTokenExpirySeconds = double.Parse(config["Jwt:AccessTokenExpirySeconds"] ?? "900");
        _refreshTokenExpiryDays = int.Parse(config["Jwt:RefreshTokenExpiryDays"] ?? "30");
    }

    public string CreateAccessToken(Guid userId)
    {
        var keyBytes = Encoding.UTF8.GetBytes(_secretKey);
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim("type", "access"),
        };

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(_accessTokenExpirySeconds),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public (string rawToken, string tokenHash, DateTime expiresAt) GenerateRefreshToken()
    {
        var rawBytes = RandomNumberGenerator.GetBytes(48);
        var rawToken = Convert.ToBase64String(rawBytes)
            .Replace("+", "-").Replace("/", "_").Replace("=", ""); 

        var tokenHash = HashRefreshToken(rawToken);
        var expiresAt = DateTime.UtcNow.AddDays(_refreshTokenExpiryDays);

        return (rawToken, tokenHash, expiresAt);
    }

    public string HashRefreshToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
