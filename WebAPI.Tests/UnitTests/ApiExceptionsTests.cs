using WebAPI.Exceptions;
using Xunit;

namespace WebAPI.Tests.UnitTests;

public class ApiExceptionsTests
{
    [Fact]
    public void ForbiddenApiException_Returns403StatusCode()
    {
        var exception = new ForbiddenApiException("Account is disabled");

        Assert.Equal(403, exception.StatusCode);
        Assert.Equal("Account is disabled", exception.Message);
    }

    [Fact]
    public void ForgotPasswordRequest_CanStoreEmail()
    {
        var request = new WebAPI.DTOs.ForgotPasswordRequest
        {
            Email = "user@example.com"
        };

        Assert.Equal("user@example.com", request.Email);
    }
}
