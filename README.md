# Auth Service — Web API

## Prerequisites

Install these before starting — check each with the command shown:

| Tool | Check with | Get it from |
|---|---|---|
| .NET 8 SDK | `dotnet --version` (should show `8.x`) | https://dotnet.microsoft.com/download |
| PostgreSQL | running locally, or a connection string to a remote instance | https://www.postgresql.org/download |
| EF Core CLI tool | `dotnet ef --version` | install below if missing |

If `dotnet ef --version` fails:
```
dotnet tool install --global dotnet-ef
```

## Setup

1. **Clone the repo, then move into the API project folder:**
   ```
   cd WebApi
   ```

2. **Restore dependencies** — downloads every NuGet package the project needs:
   ```
   dotnet restore
   ```

3. **Set up your local database.** In PostgreSQL (via `psql` or pgAdmin), create a database and user for this project if you haven't already:
   ```sql
   CREATE DATABASE appdb;
   CREATE USER app_user WITH PASSWORD 'app_password';
   GRANT ALL PRIVILEGES ON DATABASE appdb TO app_user;
   ```

4. **Configure your local secrets.** These are never stored in the repo — `dotnet user-secrets` keeps them in a file on your own machine, outside the project folder entirely, so they can never accidentally get committed:
   ```
   dotnet user-secrets init
   dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=appdb;Username=app_user;Password=app_password"
   dotnet user-secrets set "Jwt:SecretKey" "<any random string, 32+ characters>"
   ```
   To generate a random value for the secret key, run this :
   ```
   openssl rand -base64 32

   ```
   This value only needs to be random and secret, not memorable — it gets replaced with a real AWS Secrets Manager value in production.

5. **Create the database tables.** This reads the model classes and generates the actual SQL to build the schema:
   ```
   dotnet ef migrations add InitialCreate
   dotnet ef database update
   ```
   You should see new tables in `appdb` afterward — `AspNetUsers`, `AspNetRoles`, and related Identity tables.

6. **Run the project:**
   ```
   dotnet run
   ```
   Watch the terminal output for a line like `Now listening on: http://localhost:5080` — note that port number.

7. **Confirm it's actually working.** Open a browser :
   ```
   http://localhost:<port from step 6>/healthz
   ```
   Expected response:
   ```json
   {"status":"ok","db":"ok"}
   ```
   If you see this, the API is running and successfully talking to the database — setup is complete.

## Day-to-day development

Once the initial setup is complete, you do not need to repeat the database and dependency setup every time.

Run the API with:

```bash
cd "Web API"
dotnet run
```

Or use the HTTPS profile:

```bash
dotnet run --launch-profile https
```

To automatically restart the API whenever code changes:

```bash
dotnet watch run
```

For day-to-day testing:

```bash
cd WebAPI.Tests
dotnet test
```

For coverage:

```bash
dotnet test --collect:"XPlat Code Coverage" --settings coverage.runsettings
```

````report
reportgenerator -reports:"TestResults/*/coverage.cobertura.xml" -targetdir:"CoverageReport" -reporttypes:Html
``````

For the lockout smoke test:

```bash
py scripts/brute_force_lockout.py
```
