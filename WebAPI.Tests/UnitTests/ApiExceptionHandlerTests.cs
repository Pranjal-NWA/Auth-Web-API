using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using WebAPI.Exceptions;
using WebAPI.Middleware;
using Xunit;

namespace WebAPI.Tests.Middleware;

public class ApiExceptionHandlerTests
{
    private static DefaultHttpContext CreateHttpContext()
    {
        var context = new DefaultHttpContext();

        context.Request.Path = "/api/v1/test";

        context.Response.Body = new MemoryStream();

        return context;
    }

    [Fact]
    public async Task TryHandleAsync_ApiException_ReturnsTrueAndProblemDetails()
    {
        // Arrange
        var context = CreateHttpContext();

        var exception = new ConflictApiException("Test conflict");

        var handler = new ApiExceptionHandler(
            NullLogger<ApiExceptionHandler>.Instance);

        // Act
        var handled = await handler.TryHandleAsync(
            context,
            exception,
            CancellationToken.None);

        // Assert
        Assert.True(handled);
        Assert.Equal(exception.StatusCode, context.Response.StatusCode);

        Assert.Equal(
            "application/json",
            context.Response.ContentType?.Split(';')[0]);
    }

    [Fact]
    public async Task TryHandleAsync_ValidationApiException_IncludesErrors()
    {
        // Arrange
        var context = CreateHttpContext();

        var errors = new[]
        {
            "Email is invalid.",
            "Password is too weak."
        };

        var exception = new ValidationApiException(errors);

        var handler = new ApiExceptionHandler(
            NullLogger<ApiExceptionHandler>.Instance);

        // Act
        var handled = await handler.TryHandleAsync(
            context,
            exception,
            CancellationToken.None);

        // Assert
        Assert.True(handled);
        Assert.Equal(exception.StatusCode, context.Response.StatusCode);

        Assert.Equal(
            "application/json",
            context.Response.ContentType?.Split(';')[0]);

        context.Response.Body.Position = 0;

        var response =
            await JsonSerializer.DeserializeAsync<JsonElement>(
                context.Response.Body);

        Assert.True(
            response.TryGetProperty("errors", out var responseErrors));

        var returnedErrors = responseErrors
            .EnumerateArray()
            .Select(x => x.GetString())
            .ToList();

        Assert.Contains("Email is invalid.", returnedErrors);
        Assert.Contains("Password is too weak.", returnedErrors);
    }

    [Fact]
    public async Task TryHandleAsync_NonApiException_Returns500()
    {
        // Arrange
        var context = CreateHttpContext();

        var exception =
            new InvalidOperationException("Unexpected error");

        var handler = new ApiExceptionHandler(
            NullLogger<ApiExceptionHandler>.Instance);

        // Act
        var handled = await handler.TryHandleAsync(
            context,
            exception,
            CancellationToken.None);

        // Assert
        Assert.True(handled);

        Assert.Equal(
            StatusCodes.Status500InternalServerError,
            context.Response.StatusCode);

        Assert.Equal(
            "application/json",
            context.Response.ContentType?.Split(';')[0]);

        context.Response.Body.Position = 0;

        var response =
            await JsonSerializer.DeserializeAsync<JsonElement>(
                context.Response.Body);

        Assert.Equal(
            "An unexpected error occurred.",
            response.GetProperty("title").GetString());

        Assert.Equal(
            "/api/v1/test",
            response.GetProperty("instance").GetString());

        Assert.Equal(
            500,
            response.GetProperty("status").GetInt32());
    }
}