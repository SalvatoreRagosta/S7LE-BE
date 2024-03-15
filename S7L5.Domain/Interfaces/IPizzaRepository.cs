using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Domain.Interfaces
{
    public interface IPizzaRepository
    {
        int AddPizza(Pizza pizza);
        void DeletePizza(int pizzaId);
        IQueryable<Pizza> GetAllPizzas();
        Pizza GetPizzaById(int pizzaId);
        IQueryable<ComponentPizza> GetComponentPizzasByComponentId(int componentId);
        void UpdatePizzaPrice(List<int> pizzaIds, Component component);
        void DeleteComponentPizzas(int pizzaId, int componentId);
        void EditPizza(Pizza editedPizza);
    }
}
