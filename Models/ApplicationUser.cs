using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace WebAPI.Models;


public class ApplicationUser : IdentityUser<Guid>
{
    [MaxLength(255)]
    public string? FullName { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool IsActive { get; set; } = true;


    public DateTime? LastLogin { get; set; }

    public List<RefreshToken> RefreshTokens { get; set; } = new();
}
