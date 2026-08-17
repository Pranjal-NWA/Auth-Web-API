namespace WebAPI.Exceptions;

public abstract class ApiException : Exception
{
    public abstract int StatusCode { get; }
    protected ApiException(string message) : base(message) { }
}

// 409 - e.g. signup with an email that's already registered.
public class ConflictApiException : ApiException
{
    public override int StatusCode => StatusCodes.Status409Conflict;
    public ConflictApiException(string message) : base(message) { }
}

// 401 - e.g. wrong password, invalid/expired/missing refresh token.
public class UnauthorizedApiException : ApiException
{
    public override int StatusCode => StatusCodes.Status401Unauthorized;
    public UnauthorizedApiException(string message) : base(message) { }
}

// 403 - e.g. account disabled (IsActive-equivalent check).
public class ForbiddenApiException : ApiException
{
    public override int StatusCode => StatusCodes.Status403Forbidden;
    public ForbiddenApiException(string message) : base(message) { }
}

// 423 Locked - Identity's lockout kicked in after too many failed
public class LockedApiException : ApiException
{
    public override int StatusCode => StatusCodes.Status423Locked;
    public LockedApiException(string message) : base(message) { }
}

// 400 - e.g. Identity's password/user validation rules rejected the
public class ValidationApiException : ApiException
{
    public override int StatusCode => StatusCodes.Status400BadRequest;
    public IEnumerable<string> Errors { get; }

    public ValidationApiException(IEnumerable<string> errors)
        : base("One or more validation errors occurred")
    {
        Errors = errors;
    }
}
