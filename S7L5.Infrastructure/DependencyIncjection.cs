using Microsoft.Extensions.DependencyInjection;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Infrastructure.Repositories;

namespace PizzeriaImpulsMVC.Infrastructure
{
    public static class DependencyIncjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services)
        {
            services.AddTransient<IAdditionRepository, AdditionRepository>();
            services.AddTransient<IComponentRepository, ComponentRepository>();
            services.AddTransient<IDrinkRepository, DrinkRepository>();
            services.AddTransient<IPizzaRepository, PizzaRepository>();
            services.AddTransient<IUserManagmentRepository, UserManagmentRepository>();
            services.AddTransient<IShoppingCartRepository, ShoppingCartRepository>();
            services.AddTransient<IReportRepository, ReportRepository>();

            return services;
        }
    }
}
