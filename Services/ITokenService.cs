using System.Security.Claims;
namespace WebAPI.Services;


public interface ITokenService
{
    string CreateAccessToken(Guid userId, IList<string> roles);
    (string rawToken, string tokenHash, DateTime expiresAt) GenerateRefreshToken();
    string HashRefreshToken(string rawToken);
}