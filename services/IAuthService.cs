using WebAPI.DTOs;
using WebAPI.Models;

namespace WebAPI.Services;

public interface IAuthService
{
    Task<ApplicationUser> SignupAsync(SignupRequest request);
    Task<(ApplicationUser user, string accessToken, string rawRefreshToken)> LoginAsync(LoginRequest request);
    Task<string> GetUserRoleAsync(ApplicationUser user);
    Task<(ApplicationUser user, string accessToken, string rawRefreshToken)> RefreshAsync(string rawRefreshToken);
}