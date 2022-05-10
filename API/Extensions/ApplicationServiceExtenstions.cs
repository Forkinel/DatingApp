using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using API.Services;
using API.Interfaces;
using API.Data;
using Microsoft.EntityFrameworkCore;

namespace API.Extensions
{
    public static class ApplicationServiceExtenstions
    {
      public static IServiceCollection AddApplicationServices(this IServiceCollection services , IConfiguration config){
          services.AddScoped<ITokenService, TokenService>();

            services.AddDbContext<DataContext>(options => {
              options.UseSqlite(config.GetConnectionString("DefaultConnection"));
            });

            return services;
      }
    }
}
