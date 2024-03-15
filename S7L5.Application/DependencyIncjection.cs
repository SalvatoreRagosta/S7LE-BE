using Microsoft.Extensions.DependencyInjection;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.Services;
using System.Reflection;

namespace PizzeriaImpulsMVC.Application
{
    public static class DependencyIncjection
    {
        public static IServiceCollection AddApplication (this IServiceCollection services)
        {
            services.AddTransient<IAdditionService, AdditionService>();
            services.AddTransient<IComponentService, ComponentService>();
            services.AddTransient<IDrinkService, DrinkService>();
            services.AddTransient<IPizzaService, PizzaService>();
            services.AddTransient<IUserManagmentService, UserManagmentService>();
            services.AddTransient<IShoppingCartService, ShoppingCartService>();
            services.AddTransient<IReportService, ReportService>();
            services.AddAutoMapper(Assembly.GetExecutingAssembly());

            return services;
        }
    }
}
