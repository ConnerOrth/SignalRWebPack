using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using SignalRWebPack.Hubs;

namespace SignalRWebPack
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSignalR();
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder.AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod());

                options.AddPolicy("SignalRCorsPolicy",
                    builder => builder.SetIsOriginAllowed((origin) =>
                    {
                        bool result = origin.Contains("localhost") || origin.Contains("null");

                        return result;
                    })
                    .SetIsOriginAllowedToAllowWildcardSubdomains()
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials());
            });
            services.AddTransient<ICorsService, CorsService>();
            services.AddTransient<ICorsPolicyProvider, DefaultCorsPolicyProvider>();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();
            app.UseCors("CorsPolicy");
            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapHub<ChatHub>("/chathub")
                .RequireCors("SignalRCorsPolicy");
            });
        }
    }

    public class CorsMiddleware
    {
        // Property key is used by other systems, e.g. MVC, to check if CORS middleware has run
        private const string CorsMiddlewareWithEndpointInvokedKey = "__CorsMiddlewareWithEndpointInvoked";
        private static readonly object CorsMiddlewareWithEndpointInvokedValue = new object();

        private readonly Func<object, Task> OnResponseStartingDelegate = OnResponseStarting;
        private readonly RequestDelegate _next;
        private readonly CorsPolicy _policy;
        private readonly string _corsPolicyName;

        /// <summary>
        /// Instantiates a new <see cref="CorsMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="corsService">An instance of <see cref="ICorsService"/>.</param>
        /// <param name="loggerFactory">An instance of <see cref="ILoggerFactory"/>.</param>
        public CorsMiddleware(
            RequestDelegate next,
            ICorsService corsService,
            ILoggerFactory loggerFactory)
            : this(next, corsService, loggerFactory, policyName: null)
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="CorsMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="corsService">An instance of <see cref="ICorsService"/>.</param>
        /// <param name="loggerFactory">An instance of <see cref="ILoggerFactory"/>.</param>
        /// <param name="policyName">An optional name of the policy to be fetched.</param>
        public CorsMiddleware(
            RequestDelegate next,
            ICorsService corsService,
            ILoggerFactory loggerFactory,
            string policyName)
        {
            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            if (corsService == null)
            {
                throw new ArgumentNullException(nameof(corsService));
            }

            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            _next = next;
            CorsService = corsService;
            _corsPolicyName = policyName;
            Logger = loggerFactory.CreateLogger<CorsMiddleware>();
        }

        /// <summary>
        /// Instantiates a new <see cref="CorsMiddleware"/>.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline.</param>
        /// <param name="corsService">An instance of <see cref="ICorsService"/>.</param>
        /// <param name="policy">An instance of the <see cref="CorsPolicy"/> which can be applied.</param>
        /// <param name="loggerFactory">An instance of <see cref="ILoggerFactory"/>.</param>
        public CorsMiddleware(
            RequestDelegate next,
            ICorsService corsService,
            CorsPolicy policy,
            ILoggerFactory loggerFactory)
        {
            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            if (corsService == null)
            {
                throw new ArgumentNullException(nameof(corsService));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            _next = next;
            CorsService = corsService;
            _policy = policy;
            Logger = loggerFactory.CreateLogger<CorsMiddleware>();
        }

        private ICorsService CorsService { get; }

        private ILogger Logger { get; }

        /// <inheritdoc />
        public Task Invoke(HttpContext context, ICorsPolicyProvider corsPolicyProvider)
        {
            // CORS policy resolution rules:
            //
            // 1. If there is an endpoint with IDisableCorsAttribute then CORS is not run
            // 2. If there is an endpoint with ICorsPolicyMetadata then use its policy or if
            //    there is an endpoint with IEnableCorsAttribute that has a policy name then
            //    fetch policy by name, prioritizing it above policy on middleware
            // 3. If there is no policy on middleware then use name on middleware
            var endpoint = context.GetEndpoint();

            if (endpoint != null)
            {
                // EndpointRoutingMiddleware uses this flag to check if the CORS middleware processed CORS metadata on the endpoint.
                // The CORS middleware can only make this claim if it observes an actual endpoint.
                context.Items[CorsMiddlewareWithEndpointInvokedKey] = CorsMiddlewareWithEndpointInvokedValue;
            }

            if (!context.Request.Headers.ContainsKey(CorsConstants.Origin))
            {
                return _next(context);
            }

            // Get the most significant CORS metadata for the endpoint
            // For backwards compatibility reasons this is then downcast to Enable/Disable metadata
            var corsMetadata = endpoint?.Metadata.GetMetadata<ICorsMetadata>();

            if (corsMetadata is IDisableCorsAttribute)
            {
                var isOptionsRequest = HttpMethods.IsOptions(context.Request.Method);

                var isCorsPreflightRequest = isOptionsRequest && context.Request.Headers.ContainsKey(CorsConstants.AccessControlRequestMethod);

                if (isCorsPreflightRequest)
                {
                    // If this is a preflight request, and we disallow CORS, complete the request
                    context.Response.StatusCode = StatusCodes.Status204NoContent;
                    return Task.CompletedTask;
                }

                return _next(context);
            }

            var corsPolicy = _policy;
            var policyName = _corsPolicyName;
            if (corsMetadata is ICorsPolicyMetadata corsPolicyMetadata)
            {
                policyName = null;
                corsPolicy = corsPolicyMetadata.Policy;
            }
            else if (corsMetadata is IEnableCorsAttribute enableCorsAttribute &&
                enableCorsAttribute.PolicyName != null)
            {
                // If a policy name has been provided on the endpoint metadata then prioritizing it above the static middleware policy
                policyName = enableCorsAttribute.PolicyName;
                corsPolicy = null;
            }

            if (corsPolicy == null)
            {
                // Resolve policy by name if the local policy is not being used
                var policyTask = corsPolicyProvider.GetPolicyAsync(context, policyName);
                if (!policyTask.IsCompletedSuccessfully)
                {
                    return InvokeCoreAwaited(context, policyTask);
                }

                corsPolicy = policyTask.Result;
            }

            return EvaluateAndApplyPolicy(context, corsPolicy);

            async Task InvokeCoreAwaited(HttpContext context, Task<CorsPolicy> policyTask)
            {
                var corsPolicy = await policyTask;
                await EvaluateAndApplyPolicy(context, corsPolicy);
            }
        }

        private Task EvaluateAndApplyPolicy(HttpContext context, CorsPolicy corsPolicy)
        {
            if (corsPolicy == null)
            {
                //Logger.NoCorsPolicyFound();
                return _next(context);
            }

            var corsResult = CorsService.EvaluatePolicy(context, corsPolicy);
            if (corsResult.IsPreflightRequest)
            {
                CorsService.ApplyResult(corsResult, context.Response);

                // Since there is a policy which was identified,
                // always respond to preflight requests.
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return Task.CompletedTask;
            }
            else
            {
                context.Response.OnStarting(OnResponseStartingDelegate, Tuple.Create(this, context, corsResult));
                return _next(context);
            }
        }

        private static Task OnResponseStarting(object state)
        {
            var (middleware, context, result) = (Tuple<CorsMiddleware, HttpContext, CorsResult>)state;
            try
            {
                middleware.CorsService.ApplyResult(result, context.Response);
            }
            catch (Exception exception)
            {
                //middleware.Logger.FailedToSetCorsHeaders(exception);
            }
            return Task.CompletedTask;
        }
    }

    public static class CorsMiddlewareExtensions
    {
        /// <summary>
        /// Adds a CORS middleware to your web application pipeline to allow cross domain requests.
        /// </summary>
        /// <param name="app">The IApplicationBuilder passed to your Configure method</param>
        /// <returns>The original app parameter</returns>
        public static IApplicationBuilder UseCors(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<CorsMiddleware>();
        }

        /// <summary>
        /// Adds a CORS middleware to your web application pipeline to allow cross domain requests.
        /// </summary>
        /// <param name="app">The IApplicationBuilder passed to your Configure method</param>
        /// <param name="policyName">The policy name of a configured policy.</param>
        /// <returns>The original app parameter</returns>
        public static IApplicationBuilder UseCors(this IApplicationBuilder app, string policyName)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<CorsMiddleware>(policyName);
        }

        /// <summary>
        /// Adds a CORS middleware to your web application pipeline to allow cross domain requests.
        /// </summary>
        /// <param name="app">The IApplicationBuilder passed to your Configure method.</param>
        /// <param name="configurePolicy">A delegate which can use a policy builder to build a policy.</param>
        /// <returns>The original app parameter</returns>
        public static IApplicationBuilder UseCors(
            this IApplicationBuilder app,
            Action<CorsPolicyBuilder> configurePolicy)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (configurePolicy == null)
            {
                throw new ArgumentNullException(nameof(configurePolicy));
            }

            var policyBuilder = new CorsPolicyBuilder();
            configurePolicy(policyBuilder);
            return app.UseMiddleware<CorsMiddleware>(policyBuilder.Build());
        }
    }
    /// <summary>
    /// CORS extension methods for <see cref="IEndpointConventionBuilder"/>.
    /// </summary>
    public static class CorsEndpointConventionBuilderExtensions
    {
        /// <summary>
        /// Adds a CORS policy with the specified name to the endpoint(s).
        /// </summary>
        /// <param name="builder">The endpoint convention builder.</param>
        /// <param name="policyName">The CORS policy name.</param>
        /// <returns>The original convention builder parameter.</returns>
        public static TBuilder RequireCors<TBuilder>(this TBuilder builder, string policyName) where TBuilder : IEndpointConventionBuilder
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Add(endpointBuilder =>
            {
                endpointBuilder.Metadata.Add(new EnableCorsAttribute(policyName));
            });
            return builder;
        }

        /// <summary>
        /// Adds the specified CORS policy to the endpoint(s).
        /// </summary>
        /// <param name="builder">The endpoint convention builder.</param>
        /// <param name="configurePolicy">A delegate which can use a policy builder to build a policy.</param>
        /// <returns>The original convention builder parameter.</returns>
        public static TBuilder RequireCors<TBuilder>(this TBuilder builder, Action<CorsPolicyBuilder> configurePolicy) where TBuilder : IEndpointConventionBuilder
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configurePolicy == null)
            {
                throw new ArgumentNullException(nameof(configurePolicy));
            }

            var policyBuilder = new CorsPolicyBuilder();
            configurePolicy(policyBuilder);
            var policy = policyBuilder.Build();

            builder.Add(endpointBuilder =>
            {
                endpointBuilder.Metadata.Add(new CorsPolicyMetadata(policy));
            });
            return builder;
        }
    }
    public class CorsService : ICorsService
    {
        private readonly CorsOptions _options;
        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new instance of the <see cref="CorsService"/>.
        /// </summary>
        /// <param name="options">The option model representing <see cref="CorsOptions"/>.</param>
        /// <param name="loggerFactory">The <see cref="ILoggerFactory"/>.</param>
        public CorsService(IOptions<CorsOptions> options, ILoggerFactory loggerFactory)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            _options = options.Value;
            _logger = loggerFactory.CreateLogger<CorsService>();
        }

        /// <summary>
        /// Looks up a policy using the <paramref name="policyName"/> and then evaluates the policy using the passed in
        /// <paramref name="context"/>.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="policyName"></param>
        /// <returns>A <see cref="CorsResult"/> which contains the result of policy evaluation and can be
        /// used by the caller to set appropriate response headers.</returns>
        public CorsResult EvaluatePolicy(HttpContext context, string policyName)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var policy = _options.GetPolicy(policyName);
            return EvaluatePolicy(context, policy);
        }

        /// <inheritdoc />
        public CorsResult EvaluatePolicy(HttpContext context, CorsPolicy policy)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            if (policy.AllowAnyOrigin && policy.SupportsCredentials)
            {
                //throw new ArgumentException(Resources.InsecureConfiguration, nameof(policy));
            }

            var requestHeaders = context.Request.Headers;
            var origin = requestHeaders[CorsConstants.Origin];

            var isOptionsRequest = HttpMethods.IsOptions(context.Request.Method);
            var isPreflightRequest = isOptionsRequest && requestHeaders.ContainsKey(CorsConstants.AccessControlRequestMethod);

            if (isOptionsRequest && !isPreflightRequest)
            {
                //_logger.IsNotPreflightRequest();
            }

            var corsResult = new CorsResult
            {
                IsPreflightRequest = isPreflightRequest,
                IsOriginAllowed = IsOriginAllowed(policy, origin),
            };

            if (isPreflightRequest)
            {
                EvaluatePreflightRequest(context, policy, corsResult);
            }
            else
            {
                EvaluateRequest(context, policy, corsResult);
            }

            return corsResult;
        }

        private static void PopulateResult(HttpContext context, CorsPolicy policy, CorsResult result)
        {
            var headers = context.Request.Headers;
            if (policy.AllowAnyOrigin)
            {
                result.AllowedOrigin = CorsConstants.AnyOrigin;
                result.VaryByOrigin = policy.SupportsCredentials;
            }
            else
            {
                var origin = headers[CorsConstants.Origin];
                result.AllowedOrigin = origin;
                result.VaryByOrigin = policy.Origins.Count > 1;
            }

            result.SupportsCredentials = policy.SupportsCredentials;
            result.PreflightMaxAge = policy.PreflightMaxAge;

            // https://fetch.spec.whatwg.org/#http-new-header-syntax
            AddHeaderValues(result.AllowedExposedHeaders, policy.ExposedHeaders);

            var allowedMethods = policy.AllowAnyMethod ?
                new[] { result.IsPreflightRequest ? (string)headers[CorsConstants.AccessControlRequestMethod] : context.Request.Method } :
                policy.Methods;
            AddHeaderValues(result.AllowedMethods, allowedMethods);

            var allowedHeaders = policy.AllowAnyHeader ?
                headers.GetCommaSeparatedValues(CorsConstants.AccessControlRequestHeaders) :
                policy.Headers;
            AddHeaderValues(result.AllowedHeaders, allowedHeaders);
        }

        public virtual void EvaluateRequest(HttpContext context, CorsPolicy policy, CorsResult result)
        {
            PopulateResult(context, policy, result);
        }

        public virtual void EvaluatePreflightRequest(HttpContext context, CorsPolicy policy, CorsResult result)
        {
            PopulateResult(context, policy, result);
        }

        /// <inheritdoc />
        public virtual void ApplyResult(CorsResult result, HttpResponse response)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            if (!result.IsOriginAllowed)
            {
                // In case a server does not wish to participate in the CORS protocol, its HTTP response to the
                // CORS or CORS-preflight request must not include any of the above headers.
                return;
            }

            var headers = response.Headers;
            headers[CorsConstants.AccessControlAllowOrigin] = result.AllowedOrigin;

            if (result.SupportsCredentials)
            {
                headers[CorsConstants.AccessControlAllowCredentials] = "true";
            }

            if (result.IsPreflightRequest)
            {
                //_logger.IsPreflightRequest();

                // An HTTP response to a CORS-preflight request can include the following headers:
                // `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Max-Age`
                if (result.AllowedHeaders.Count > 0)
                {
                    headers.SetCommaSeparatedValues(CorsConstants.AccessControlAllowHeaders, result.AllowedHeaders.ToArray());
                }

                if (result.AllowedMethods.Count > 0)
                {
                    headers.SetCommaSeparatedValues(CorsConstants.AccessControlAllowMethods, result.AllowedMethods.ToArray());
                }

                if (result.PreflightMaxAge.HasValue)
                {
                    headers[CorsConstants.AccessControlMaxAge] = result.PreflightMaxAge.Value.TotalSeconds.ToString(CultureInfo.InvariantCulture);
                }
            }
            else
            {
                // An HTTP response to a CORS request that is not a CORS-preflight request can also include the following header:
                // `Access-Control-Expose-Headers`
                if (result.AllowedExposedHeaders.Count > 0)
                {
                    headers.SetCommaSeparatedValues(CorsConstants.AccessControlExposeHeaders, result.AllowedExposedHeaders.ToArray());
                }
            }

            if (result.VaryByOrigin)
            {
                headers.Append("Vary", "Origin");
            }
        }

        private static void AddHeaderValues(IList<string> target, IList<string> headerValues)
        {
            if (headerValues == null)
            {
                return;
            }

            for (var i = 0; i < headerValues.Count; i++)
            {
                target.Add(headerValues[i]);
            }
        }

        private bool IsOriginAllowed(CorsPolicy policy, StringValues origin)
        {
            if (StringValues.IsNullOrEmpty(origin))
            {
                //_logger.RequestDoesNotHaveOriginHeader();
                return false;
            }

            //_logger.RequestHasOriginHeader(origin);
            if (policy.AllowAnyOrigin || policy.IsOriginAllowed(origin))
            {
                //_logger.PolicySuccess();
                return true;
            }
            //_logger.PolicyFailure();
            //_logger.OriginNotAllowed(origin);
            return false;
        }
    }
    public interface ICorsService
    {
        /// <summary>
        /// Evaluates the given <paramref name="policy"/> using the passed in <paramref name="context"/>.
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/> associated with the call.</param>
        /// <param name="policy">The <see cref="CorsPolicy"/> which needs to be evaluated.</param>
        /// <returns>A <see cref="CorsResult"/> which contains the result of policy evaluation and can be
        /// used by the caller to set appropriate response headers.</returns>
        CorsResult EvaluatePolicy(HttpContext context, CorsPolicy policy);


        /// <summary>
        /// Adds CORS-specific response headers to the given <paramref name="response"/>.
        /// </summary>
        /// <param name="result">The <see cref="CorsResult"/> used to read the allowed values.</param>
        /// <param name="response">The <see cref="HttpResponse"/> associated with the current call.</param>
        void ApplyResult(CorsResult result, HttpResponse response);

    }

    public class CorsPolicy
    {
        private TimeSpan? _preflightMaxAge;

        /// <summary>
        /// Default constructor for a CorsPolicy.
        /// </summary>
        public CorsPolicy()
        {
            IsOriginAllowed = DefaultIsOriginAllowed;
        }

        /// <summary>
        /// Gets a value indicating if all headers are allowed.
        /// </summary>
        public bool AllowAnyHeader
        {
            get
            {
                if (Headers == null || Headers.Count != 1 || Headers.Count == 1 && Headers[0] != "*")
                {
                    return false;
                }

                return true;
            }
        }

        /// <summary>
        /// Gets a value indicating if all methods are allowed.
        /// </summary>
        public bool AllowAnyMethod
        {
            get
            {
                if (Methods == null || Methods.Count != 1 || Methods.Count == 1 && Methods[0] != "*")
                {
                    return false;
                }

                return true;
            }
        }

        /// <summary>
        /// Gets a value indicating if all origins are allowed.
        /// </summary>
        public bool AllowAnyOrigin
        {
            get
            {
                if (Origins == null || Origins.Count != 1 || Origins.Count == 1 && Origins[0] != "*")
                {
                    return false;
                }

                return true;
            }
        }

        /// <summary>
        /// Gets or sets a function which evaluates whether an origin is allowed.
        /// </summary>
        public Func<string, bool> IsOriginAllowed { get; set; }

        /// <summary>
        /// Gets the headers that the resource might use and can be exposed.
        /// </summary>
        public IList<string> ExposedHeaders { get; } = new List<string>();

        /// <summary>
        /// Gets the headers that are supported by the resource.
        /// </summary>
        public IList<string> Headers { get; } = new List<string>();

        /// <summary>
        /// Gets the methods that are supported by the resource.
        /// </summary>
        public IList<string> Methods { get; } = new List<string>();

        /// <summary>
        /// Gets the origins that are allowed to access the resource.
        /// </summary>
        public IList<string> Origins { get; } = new List<string>();

        /// <summary>
        /// Gets or sets the <see cref="TimeSpan"/> for which the results of a preflight request can be cached.
        /// </summary>
        public TimeSpan? PreflightMaxAge
        {
            get
            {
                return _preflightMaxAge;
            }
            set
            {
                if (value < TimeSpan.Zero)
                {
                    //throw new ArgumentOutOfRangeException(nameof(value), Resources.PreflightMaxAgeOutOfRange);
                }

                _preflightMaxAge = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the resource supports user credentials in the request.
        /// </summary>
        public bool SupportsCredentials { get; set; }

        /// <summary>
        /// Returns a <see cref="System.String" /> that represents this instance.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            var builder = new StringBuilder();
            builder.Append("AllowAnyHeader: ");
            builder.Append(AllowAnyHeader);
            builder.Append(", AllowAnyMethod: ");
            builder.Append(AllowAnyMethod);
            builder.Append(", AllowAnyOrigin: ");
            builder.Append(AllowAnyOrigin);
            builder.Append(", PreflightMaxAge: ");
            builder.Append(PreflightMaxAge.HasValue ?
                PreflightMaxAge.Value.TotalSeconds.ToString() : "null");
            builder.Append(", SupportsCredentials: ");
            builder.Append(SupportsCredentials);
            builder.Append(", Origins: {");
            builder.Append(string.Join(",", Origins));
            builder.Append("}");
            builder.Append(", Methods: {");
            builder.Append(string.Join(",", Methods));
            builder.Append("}");
            builder.Append(", Headers: {");
            builder.Append(string.Join(",", Headers));
            builder.Append("}");
            builder.Append(", ExposedHeaders: {");
            builder.Append(string.Join(",", ExposedHeaders));
            builder.Append("}");
            return builder.ToString();
        }

        private bool DefaultIsOriginAllowed(string origin)
        {
            return Origins.Contains(origin, StringComparer.Ordinal);
        }
    }
    public class CorsOptions
    {
        private string _defaultPolicyName = "__DefaultCorsPolicy";

        // DefaultCorsPolicyProvider returns a Task<CorsPolicy>. We'll cache the value to be returned alongside
        // the actual policy instance to have a separate lookup.
        internal IDictionary<string, (CorsPolicy policy, Task<CorsPolicy> policyTask)> PolicyMap { get; }
            = new Dictionary<string, (CorsPolicy, Task<CorsPolicy>)>(StringComparer.Ordinal);

        public string DefaultPolicyName
        {
            get => _defaultPolicyName;
            set
            {
                _defaultPolicyName = value ?? throw new ArgumentNullException(nameof(value));
            }
        }

        /// <summary>
        /// Adds a new policy and sets it as the default.
        /// </summary>
        /// <param name="policy">The <see cref="CorsPolicy"/> policy to be added.</param>
        public void AddDefaultPolicy(CorsPolicy policy)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            AddPolicy(DefaultPolicyName, policy);
        }

        /// <summary>
        /// Adds a new policy and sets it as the default.
        /// </summary>
        /// <param name="configurePolicy">A delegate which can use a policy builder to build a policy.</param>
        public void AddDefaultPolicy(Action<CorsPolicyBuilder> configurePolicy)
        {
            if (configurePolicy == null)
            {
                throw new ArgumentNullException(nameof(configurePolicy));
            }

            AddPolicy(DefaultPolicyName, configurePolicy);
        }

        /// <summary>
        /// Adds a new policy.
        /// </summary>
        /// <param name="name">The name of the policy.</param>
        /// <param name="policy">The <see cref="CorsPolicy"/> policy to be added.</param>
        public void AddPolicy(string name, CorsPolicy policy)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            PolicyMap[name] = (policy, Task.FromResult(policy));
        }

        /// <summary>
        /// Adds a new policy.
        /// </summary>
        /// <param name="name">The name of the policy.</param>
        /// <param name="configurePolicy">A delegate which can use a policy builder to build a policy.</param>
        public void AddPolicy(string name, Action<CorsPolicyBuilder> configurePolicy)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (configurePolicy == null)
            {
                throw new ArgumentNullException(nameof(configurePolicy));
            }

            var policyBuilder = new CorsPolicyBuilder();
            configurePolicy(policyBuilder);
            var policy = policyBuilder.Build();

            PolicyMap[name] = (policy, Task.FromResult(policy));
        }

        /// <summary>
        /// Gets the policy based on the <paramref name="name"/>
        /// </summary>
        /// <param name="name">The name of the policy to lookup.</param>
        /// <returns>The <see cref="CorsPolicy"/> if the policy was added.<c>null</c> otherwise.</returns>
        public CorsPolicy GetPolicy(string name)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (PolicyMap.TryGetValue(name, out var result))
            {
                return result.policy;
            }

            return null;
        }
    }
    public interface ICorsPolicyProvider
    {
        /// <summary>
        /// Gets a <see cref="CorsPolicy"/> from the given <paramref name="context"/>
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/> associated with this call.</param>
        /// <param name="policyName">An optional policy name to look for.</param>
        /// <returns>A <see cref="CorsPolicy"/></returns>
        Task<CorsPolicy> GetPolicyAsync(HttpContext context, string policyName);
    }
    /// <inheritdoc />
    public class DefaultCorsPolicyProvider : ICorsPolicyProvider
    {
        private static readonly Task<CorsPolicy> NullResult = Task.FromResult<CorsPolicy>(null);
        private readonly CorsOptions _options;

        /// <summary>
        /// Creates a new instance of <see cref="DefaultCorsPolicyProvider"/>.
        /// </summary>
        /// <param name="options">The options configured for the application.</param>
        public DefaultCorsPolicyProvider(IOptions<CorsOptions> options)
        {
            _options = options.Value;
        }

        /// <inheritdoc />
        public Task<CorsPolicy> GetPolicyAsync(HttpContext context, string policyName)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            policyName ??= _options.DefaultPolicyName;
            if (_options.PolicyMap.TryGetValue(policyName, out var result))
            {
                return result.policyTask;
            }

            return NullResult;
        }
    }
    public interface ICorsPolicyMetadata : ICorsMetadata
    {
        /// <summary>
        /// The policy which needs to be applied.
        /// </summary>
        CorsPolicy Policy { get; }
    }
    public class CorsPolicyBuilder
    {
        private readonly CorsPolicy _policy = new CorsPolicy();

        /// <summary>
        /// Creates a new instance of the <see cref="CorsPolicyBuilder"/>.
        /// </summary>
        /// <param name="origins">list of origins which can be added.</param>
        /// <remarks> <see cref="WithOrigins(string[])"/> for details on normalizing the origin value.</remarks>
        public CorsPolicyBuilder(params string[] origins)
        {
            WithOrigins(origins);
        }

        /// <summary>
        /// Creates a new instance of the <see cref="CorsPolicyBuilder"/>.
        /// </summary>
        /// <param name="policy">The policy which will be used to intialize the builder.</param>
        public CorsPolicyBuilder(CorsPolicy policy)
        {
            Combine(policy);
        }

        /// <summary>
        /// Adds the specified <paramref name="origins"/> to the policy.
        /// </summary>
        /// <param name="origins">The origins that are allowed.</param>
        /// <returns>The current policy builder.</returns>
        /// <remarks>
        /// This method normalizes the origin value prior to adding it to <see cref="CorsPolicy.Origins"/> to match
        /// the normalization performed by the browser on the value sent in the <c>ORIGIN</c> header.
        /// <list type="bullet">
        /// <item>
        /// If the specified origin has an internationalized domain name (IDN), the punycoded value is used. If the origin
        /// specifies a default port (e.g. 443 for HTTPS or 80 for HTTP), this will be dropped as part of normalization.
        /// Finally, the scheme and punycoded host name are culture invariant lower cased before being added to the <see cref="CorsPolicy.Origins"/>
        /// collection.
        /// </item>
        /// <item>
        /// For all other origins, normalization involves performing a culture invariant lower casing of the host name.
        /// </item>
        /// </list>
        /// </remarks>
        public CorsPolicyBuilder WithOrigins(params string[] origins)
        {
            foreach (var origin in origins)
            {
                var normalizedOrigin = GetNormalizedOrigin(origin);
                _policy.Origins.Add(normalizedOrigin);
            }

            return this;
        }

        internal static string GetNormalizedOrigin(string origin)
        {
            if (Uri.TryCreate(origin, UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps) &&
                !string.Equals(uri.IdnHost, uri.Host, StringComparison.Ordinal))
            {
                var builder = new UriBuilder(uri.Scheme.ToLowerInvariant(), uri.IdnHost.ToLowerInvariant());
                if (!uri.IsDefaultPort)
                {
                    // Uri does not have a way to differentiate between a port value inferred by default (e.g. Port = 80 for http://www.example.com) and
                    // a default port value that is specified (e.g. Port = 80 for http://www.example.com:80). Although the HTTP or FETCH spec does not say 
                    // anything about including the default port as part of the Origin header, at the time of writing, browsers drop "default" port when navigating
                    // and when sending the Origin header. All this goes to say, it appears OK to drop an explicitly specified port, 
                    // if it is the default port when working with an IDN host.
                    builder.Port = uri.Port;
                }

                return builder.Uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped);
            }

            return origin.ToLowerInvariant();
        }

        /// <summary>
        /// Adds the specified <paramref name="headers"/> to the policy.
        /// </summary>
        /// <param name="headers">The headers which need to be allowed in the request.</param>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder WithHeaders(params string[] headers)
        {
            foreach (var req in headers)
            {
                _policy.Headers.Add(req);
            }
            return this;
        }

        /// <summary>
        /// Adds the specified <paramref name="exposedHeaders"/> to the policy.
        /// </summary>
        /// <param name="exposedHeaders">The headers which need to be exposed to the client.</param>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder WithExposedHeaders(params string[] exposedHeaders)
        {
            foreach (var req in exposedHeaders)
            {
                _policy.ExposedHeaders.Add(req);
            }

            return this;
        }

        /// <summary>
        /// Adds the specified <paramref name="methods"/> to the policy.
        /// </summary>
        /// <param name="methods">The methods which need to be added to the policy.</param>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder WithMethods(params string[] methods)
        {
            foreach (var req in methods)
            {
                _policy.Methods.Add(req);
            }

            return this;
        }

        /// <summary>
        /// Sets the policy to allow credentials.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder AllowCredentials()
        {
            _policy.SupportsCredentials = true;
            return this;
        }

        /// <summary>
        /// Sets the policy to not allow credentials.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder DisallowCredentials()
        {
            _policy.SupportsCredentials = false;
            return this;
        }

        /// <summary>
        /// Ensures that the policy allows any origin.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder AllowAnyOrigin()
        {
            _policy.Origins.Clear();
            _policy.Origins.Add(CorsConstants.AnyOrigin);
            return this;
        }

        /// <summary>
        /// Ensures that the policy allows any method.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder AllowAnyMethod()
        {
            _policy.Methods.Clear();
            _policy.Methods.Add("*");
            return this;
        }

        /// <summary>
        /// Ensures that the policy allows any header.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder AllowAnyHeader()
        {
            _policy.Headers.Clear();
            _policy.Headers.Add("*");
            return this;
        }

        /// <summary>
        /// Sets the preflightMaxAge for the underlying policy.
        /// </summary>
        /// <param name="preflightMaxAge">A positive <see cref="TimeSpan"/> indicating the time a preflight
        /// request can be cached.</param>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder SetPreflightMaxAge(TimeSpan preflightMaxAge)
        {
            _policy.PreflightMaxAge = preflightMaxAge;
            return this;
        }

        /// <summary>
        /// Sets the specified <paramref name="isOriginAllowed"/> for the underlying policy.
        /// </summary>
        /// <param name="isOriginAllowed">The function used by the policy to evaluate if an origin is allowed.</param>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder SetIsOriginAllowed(Func<string, bool> isOriginAllowed)
        {
            _policy.IsOriginAllowed = isOriginAllowed;
            return this;
        }

        /// <summary>
        /// Sets the <see cref="CorsPolicy.IsOriginAllowed"/> property of the policy to be a function
        /// that allows origins to match a configured wildcarded domain when evaluating if the 
        /// origin is allowed.
        /// </summary>
        /// <returns>The current policy builder.</returns>
        public CorsPolicyBuilder SetIsOriginAllowedToAllowWildcardSubdomains()
        {
            _policy.IsOriginAllowed = _policy.IsOriginAnAllowedSubdomain;
            return this;
        }

        /// <summary>
        /// Builds a new <see cref="CorsPolicy"/> using the entries added.
        /// </summary>
        /// <returns>The constructed <see cref="CorsPolicy"/>.</returns>
        public CorsPolicy Build()
        {
            if (_policy.AllowAnyOrigin && _policy.SupportsCredentials)
            {
                //throw new InvalidOperationException(Resources.InsecureConfiguration);
            }

            return _policy;
        }

        /// <summary>
        /// Combines the given <paramref name="policy"/> to the existing properties in the builder.
        /// </summary>
        /// <param name="policy">The policy which needs to be combined.</param>
        /// <returns>The current policy builder.</returns>
        private CorsPolicyBuilder Combine(CorsPolicy policy)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            WithOrigins(policy.Origins.ToArray());
            WithHeaders(policy.Headers.ToArray());
            WithExposedHeaders(policy.ExposedHeaders.ToArray());
            WithMethods(policy.Methods.ToArray());
            SetIsOriginAllowed(policy.IsOriginAllowed);

            if (policy.PreflightMaxAge.HasValue)
            {
                SetPreflightMaxAge(policy.PreflightMaxAge.Value);
            }

            if (policy.SupportsCredentials)
            {
                AllowCredentials();
            }
            else
            {
                DisallowCredentials();
            }

            return this;
        }
    }
    internal static class CorsPolicyExtensions
    {
        private const string _WildcardSubdomain = "*.";

        public static bool IsOriginAnAllowedSubdomain(this CorsPolicy policy, string origin)
        {
            if (policy.Origins.Contains(origin))
            {
                return true;
            }

            if (Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
            {
                return policy.Origins
                    .Where(o => o.Contains($"://{_WildcardSubdomain}"))
                    .Select(CreateDomainUri)
                    .Any(domain => UriHelpers.IsSubdomainOf(originUri, domain));
            }

            return false;
        }

        private static Uri CreateDomainUri(string origin)
        {
            return new Uri(origin.Replace(_WildcardSubdomain, string.Empty), UriKind.Absolute);
        }
    }
    internal static class UriHelpers
    {
        public static bool IsSubdomainOf(Uri subdomain, Uri domain)
        {
            return subdomain.IsAbsoluteUri
                && domain.IsAbsoluteUri
                && subdomain.Scheme == domain.Scheme
                && subdomain.Port == domain.Port
                && subdomain.Host.EndsWith($".{domain.Host}", StringComparison.Ordinal);
        }
    }
    public class CorsPolicyMetadata : ICorsPolicyMetadata
    {
        public CorsPolicyMetadata(CorsPolicy policy)
        {
            Policy = policy;
        }

        /// <summary>
        /// The policy which needs to be applied.
        /// </summary>
        public CorsPolicy Policy { get; }
    }
    internal static class CORSLoggerExtensions
    {
        private static readonly Action<ILogger, Exception> _isPreflightRequest;
        private static readonly Action<ILogger, string, Exception> _requestHasOriginHeader;
        private static readonly Action<ILogger, Exception> _requestDoesNotHaveOriginHeader;
        private static readonly Action<ILogger, Exception> _policySuccess;
        private static readonly Action<ILogger, Exception> _policyFailure;
        private static readonly Action<ILogger, string, Exception> _originNotAllowed;
        private static readonly Action<ILogger, string, Exception> _accessControlMethodNotAllowed;
        private static readonly Action<ILogger, string, Exception> _requestHeaderNotAllowed;
        private static readonly Action<ILogger, Exception> _failedToSetCorsHeaders;
        private static readonly Action<ILogger, Exception> _noCorsPolicyFound;
        private static readonly Action<ILogger, Exception> _isNotPreflightRequest;

        static CORSLoggerExtensions()
        {
            _isPreflightRequest = LoggerMessage.Define(
                LogLevel.Debug,
                new EventId(1, "IsPreflightRequest"),
                "The request is a preflight request.");

            _requestHasOriginHeader = LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(2, "RequestHasOriginHeader"),
                "The request has an origin header: '{origin}'.");

            _requestDoesNotHaveOriginHeader = LoggerMessage.Define(
                LogLevel.Debug,
                new EventId(3, "RequestDoesNotHaveOriginHeader"),
                "The request does not have an origin header.");

            _policySuccess = LoggerMessage.Define(
                LogLevel.Information,
                new EventId(4, "PolicySuccess"),
                "CORS policy execution successful.");

            _policyFailure = LoggerMessage.Define(
                LogLevel.Information,
                new EventId(5, "PolicyFailure"),
                "CORS policy execution failed.");

            _originNotAllowed = LoggerMessage.Define<string>(
                LogLevel.Information,
                new EventId(6, "OriginNotAllowed"),
                "Request origin {origin} does not have permission to access the resource.");

            _accessControlMethodNotAllowed = LoggerMessage.Define<string>(
                LogLevel.Information,
                new EventId(7, "AccessControlMethodNotAllowed"),
                "Request method {accessControlRequestMethod} not allowed in CORS policy.");

            _requestHeaderNotAllowed = LoggerMessage.Define<string>(
                LogLevel.Information,
                new EventId(8, "RequestHeaderNotAllowed"),
                "Request header '{requestHeader}' not allowed in CORS policy.");

            _failedToSetCorsHeaders = LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(9, "FailedToSetCorsHeaders"),
                "Failed to apply CORS Response headers.");

            _noCorsPolicyFound = LoggerMessage.Define(
                LogLevel.Information,
                new EventId(10, "NoCorsPolicyFound"),
                "No CORS policy found for the specified request.");

            _isNotPreflightRequest = LoggerMessage.Define(
                LogLevel.Debug,
                new EventId(12, "IsNotPreflightRequest"),
                "This request uses the HTTP OPTIONS method but does not have an Access-Control-Request-Method header. This request will not be treated as a CORS preflight request.");
        }

        public static void IsPreflightRequest(this ILogger logger)
        {
            _isPreflightRequest(logger, null);
        }

        public static void RequestHasOriginHeader(this ILogger logger, string origin)
        {
            _requestHasOriginHeader(logger, origin, null);
        }

        public static void RequestDoesNotHaveOriginHeader(this ILogger logger)
        {
            _requestDoesNotHaveOriginHeader(logger, null);
        }

        public static void PolicySuccess(this ILogger logger)
        {
            _policySuccess(logger, null);
        }

        public static void PolicyFailure(this ILogger logger)
        {
            _policyFailure(logger, null);
        }

        public static void OriginNotAllowed(this ILogger logger, string origin)
        {
            _originNotAllowed(logger, origin, null);
        }

        public static void AccessControlMethodNotAllowed(this ILogger logger, string accessControlMethod)
        {
            _accessControlMethodNotAllowed(logger, accessControlMethod, null);
        }

        public static void RequestHeaderNotAllowed(this ILogger logger, string requestHeader)
        {
            _requestHeaderNotAllowed(logger, requestHeader, null);
        }

        public static void FailedToSetCorsHeaders(this ILogger logger, Exception exception)
        {
            _failedToSetCorsHeaders(logger, exception);
        }

        public static void NoCorsPolicyFound(this ILogger logger)
        {
            _noCorsPolicyFound(logger, null);
        }

        public static void IsNotPreflightRequest(this ILogger logger)
        {
            _isNotPreflightRequest(logger, null);
        }
    }
    public static class CorsServiceCollectionExtensions
    {
        /// <summary>
        /// Adds cross-origin resource sharing services to the specified <see cref="IServiceCollection" />.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddCors(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddOptions();

            services.TryAdd(ServiceDescriptor.Transient<ICorsService, CorsService>());
            services.TryAdd(ServiceDescriptor.Transient<ICorsPolicyProvider, DefaultCorsPolicyProvider>());

            return services;
        }

        /// <summary>
        /// Adds cross-origin resource sharing services to the specified <see cref="IServiceCollection" />.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <param name="setupAction">An <see cref="Action{CorsOptions}"/> to configure the provided <see cref="CorsOptions"/>.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddCors(this IServiceCollection services, Action<CorsOptions> setupAction)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (setupAction == null)
            {
                throw new ArgumentNullException(nameof(setupAction));
            }

            services.AddCors();
            services.Configure(setupAction);

            return services;
        }
    }
}
