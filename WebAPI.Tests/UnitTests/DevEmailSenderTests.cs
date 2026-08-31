using Microsoft.Extensions.Logging.Abstractions;
using WebAPI.Services;
using Xunit;

namespace WebAPI.Tests.UnitTests;

public class DevEmailSenderTests
{
    [Fact]
    public async Task SendEmailConfirmationAsync_CompletesSuccessfully()
    {
        var sender = new DevEmailSender(
            NullLogger<DevEmailSender>.Instance);

        var task = sender.SendEmailConfirmationAsync(
            "user@example.com",
            "https://example.com/confirm");

        await task;

        Assert.True(task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task SendPasswordResetAsync_CompletesSuccessfully()
    {
        var sender = new DevEmailSender(
            NullLogger<DevEmailSender>.Instance);

        var task = sender.SendPasswordResetAsync(
            "user@example.com",
            "https://example.com/reset");

        await task;

        Assert.True(task.IsCompletedSuccessfully);
    }
}
