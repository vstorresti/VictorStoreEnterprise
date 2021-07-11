using Microsoft.Extensions.DependencyInjection;
using Victor.WebApp.MVC.Services;
using Victor.WebApp.MVC.Services.Interfaces;

namespace Victor.WebApp.MVC.Configuration
{
    public static class DependencyInjectionConfig
    {
        public static void RegisterServices(this IServiceCollection services)
        {
            services.AddHttpClient<IAutenticacaoService, AutenticacaoService>();
        }
    }
}
