using WebAPI.DTOs;
using WebAPI.Models;
using Microsoft.AspNetCore.Identity;

namespace WebAPI.Services;

public interface IUserService
{
    Task<UserResponse?> GetProfileAsync(Guid userId);
}
