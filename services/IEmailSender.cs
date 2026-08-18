namespace WebAPI.Services;
public interface IEmailSender
{
    Task SendEmailConfirmationAsync(string toEmail, string confirmationLink);
    Task SendPasswordResetAsync(string toEmail, string resetLink);
}

public class DevEmailSender : IEmailSender
{
    private readonly ILogger<DevEmailSender> _logger;
    public DevEmailSender(ILogger<DevEmailSender> logger) => _logger = logger;

    public Task SendEmailConfirmationAsync(string toEmail, string confirmationLink)
    {
        _logger.LogInformation("[DEV EMAIL] Confirmation link for {Email}: {Link}", toEmail, confirmationLink);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetAsync(string toEmail, string resetLink)
    {
        _logger.LogInformation("[DEV EMAIL] Password reset link for {Email}: {Link}", toEmail, resetLink);
        return Task.CompletedTask;
    }
}
