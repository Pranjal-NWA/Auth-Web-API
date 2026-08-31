using WebAPI.DTOs;
using WebAPI.Models;
using Microsoft.AspNetCore.Identity;

namespace WebAPI.Services;

public class UserService : IUserService
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UserService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<UserResponse?> GetProfileAsync(Guid userId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user is null || !user.IsActive || await _userManager.IsLockedOutAsync(user))
            return null;

        return new UserResponse
        {
            Id = user.Id,
            Email = user.Email!,
            FullName = user.FullName,
            IsVerified = user.EmailConfirmed,
            Role=await _userManager.GetRolesAsync(user).ContinueWith(t => t.Result.FirstOrDefault() ?? "User"),
            CreatedAt = user.CreatedAt,
        };
    }
}
