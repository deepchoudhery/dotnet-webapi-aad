# dotnet-webapi-aad

app --> dotnet new webapi


app --> dotnet new webapi --auth SingleOrg

- appsettingsjson 
```
    - "AzureAd": {
            "Instance": "https://login.microsoftonline.com/",
            "Domain": "qualified.domain.name",
            "TenantId": "22222222-2222-2222-2222-222222222222",
            "ClientId": "11111111-1111-1111-11111111111111111",
            "CallbackPath": "/signin-oidc"
        },
```
- Startup.cs
```
    ConfigureServices(IServiceCollection)
        - services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddMicrosoftIdentityWebApi(Configuration.GetSection("AzureAd"));
        - app.UseAuthentication();
```

- csproj
    - UserSecretsId
    - PackageReferences 
        - Microsoft.AspNetCore.Authentication.JwtBearer  
        - Microsoft.AspNetCore.Authentication.OpenIdConnect
        - Microsoft.Identity.Web

- WeatherForecastController.cs
```
    - [Authorize] on class
    - // The Web API will only accept tokens 1) for users, and 2) having the "access_as_user" scope for this API
      static readonly string[] scopeRequiredByApi = new string[] { "access_as_user" };

    - HttpContext.VerifyUserHasAnyAcceptedScope(scopeRequiredByApi); in IEnumerable<WeatherForcase> Get()
```

app --> provisioned app

- appsettings.json
    - updates Domain, TenantId, ClientId


app --> dotnet new webapi --auth SingleOrg --calls-graph

- appsettingsjson 
```
    - "AzureAd": {
            "Instance": "https://login.microsoftonline.com/",
            "Domain": "qualified.domain.name",
            "TenantId": "22222222-2222-2222-2222-222222222222",
            "ClientId": "11111111-1111-1111-11111111111111111",
            "ClientSecret": "secret-from-app-registration",
            "ClientCertificates" : [
            ],
            "CallbackPath": "/signin-oidc"
        },
```
    - "DownstreamAPI": {
```
            /*
            'Scopes' contains space separated scopes of the Web API you want to call. This can be:
            - a scope for a V2 application (for instance api:b3682cc7-8b30-4bd2-aaba-080c6bf0fd31/access_as_user)
            - a scope corresponding to a V1 application (for instance <App ID URI>/.default, where  <App ID URI> is the
                App ID URI of a legacy v1 Web application
            Applications are registered in the https:portal.azure.com portal.
            */
            "BaseUrl": "https://graph.microsoft.com/v1.0",
            "Scopes": "user.read"
        },
```

- Startup.cs
    ConfigureServices(IServiceCollection)
```
        - services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddMicrosoftIdentityWebApi(Configuration.GetSection("AzureAd"))
                .EnableTokenAcquisitionToCallDownstreamApi()
                    .AddMicrosoftGraph(Configuration.GetSection("DownstreamApi"))
                    .AddInMemoryTokenCaches();
```
- csproj
    - UserSecretsId
    - PackageReferences 
        - Microsoft.AspNetCore.Authentication.JwtBearer  
        - Microsoft.AspNetCore.Authentication.OpenIdConnect
        - Microsoft.Identity.Web
        - Microsoft.Identity.Web.MicrosoftGraph

- WeatherForecastController.cs
```
    - added private GraphServiceClient _graphServiceClient;
    - contructor -> public WeatherForecastController(ILogger<WeatherForecastController> logger,
                                                    GraphServiceClient graphServiceClient)

    - public IEnumerable<WeatherForecast> Get() --> public async Task<IEnumerable<WeatherForecast>> Get()
    - public async Task<IEnumerable<WeatherForecast>> Get()
        var user = await _graphServiceClient.Me.Request().GetAsync();
```


app --> dotnet new webapi --auth SingleOrg --called-api-url https:graph.microsoft.com/beta/me --called-api-scopes user.read

- appsettingsjson 
```
    - "AzureAd": {
            "Instance": "https://login.microsoftonline.com/",
            "Domain": "qualified.domain.name",
            "TenantId": "22222222-2222-2222-2222-222222222222",
            "ClientId": "11111111-1111-1111-11111111111111111",
            "ClientSecret": "secret-from-app-registration",
            "ClientCertificates" : [
            ],
            "CallbackPath": "/signin-oidc"
        },
    - "DownstreamAPI": {
            /*
            'Scopes' contains space separated scopes of the Web API you want to call. This can be:
            - a scope for a V2 application (for instance api:b3682cc7-8b30-4bd2-aaba-080c6bf0fd31/access_as_user)
            - a scope corresponding to a V1 application (for instance <App ID URI>/.default, where  <App ID URI> is the
                App ID URI of a legacy v1 Web application
            Applications are registered in the https:portal.azure.com portal.
            */
            "BaseUrl": "https:graph.microsoft.com/beta/me", --> read from dotnet new 
            "Scopes": "user.read" --> read from dotnet new 
        },
```
- Startup.cs
    ConfigureServices(IServiceCollection)
```
         - services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddMicrosoftIdentityWebApi(Configuration.GetSection("AzureAd"))
                .EnableTokenAcquisitionToCallDownstreamApi()
                    .AddDownstreamWebApi("DownstreamApi", Configuration.GetSection("DownstreamApi"))
                    .AddInMemoryTokenCaches();
```
- csproj
    - UserSecretsId
    - PackageReferences 
        - Microsoft.AspNetCore.Authentication.JwtBearer  
        - Microsoft.AspNetCore.Authentication.OpenIdConnect
        - Microsoft.Identity.Web

- WeatherForecastController.cs
    - [Authorize] on class
```
    - added private IDownstreamWebApi _downstreamWebApi;
    - contructor -> public WeatherForecastController(ILogger<WeatherForecastController> logger,
                                                    IDownstreamWebApi downstreamWebApi)

    - public IEnumerable<WeatherForecast> Get() --> public async Task<IEnumerable<WeatherForecast>> Get()
    - public async Task<IEnumerable<WeatherForecast>> Get()
        using var response = await _downstreamWebApi.CallWebApiForUserAsync("DownstreamApi").ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.OK)
        {
            var apiResult = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            // Do something
        }
        else
        {
            var error = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            throw new HttpRequestException($"Invalid status code in the HttpResponseMessage: {response.StatusCode}: {error}");
        }
```