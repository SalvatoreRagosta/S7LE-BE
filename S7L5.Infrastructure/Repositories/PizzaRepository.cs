using Microsoft.EntityFrameworkCore;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Infrastructure.Repositories
{
    public class PizzaRepository : IPizzaRepository
    {
        private readonly Context _context;

        public PizzaRepository(Context context)
        {
            _context = context;
        }

        public int AddPizza(Pizza pizza)
        {
            _context.Pizzas.Add(pizza);
            _context.SaveChanges();

            return pizza.Id;
        }

        public void DeletePizza(int pizzaId)
        {
            var pizza = _context.Pizzas.Find(pizzaId);

            if (pizza != null)
            {
                _context.Pizzas.Remove(pizza);
                _context.SaveChanges();
            }
        }

        public IQueryable<Pizza> GetAllPizzas()
        {
            var pizzas = _context.Pizzas.Include(t => t.ComponentPizzas).ThenInclude(c => c.Component);

            return pizzas;
        }


        public Pizza GetPizzaById(int pizzaId)
        {
            var pizza = _context.Pizzas
                .Include(t => t.ComponentPizzas)
                .ThenInclude(c => c.Component)
                .FirstOrDefault(x => x.Id == pizzaId);
                
            return pizza;
        }

        public IQueryable<ComponentPizza> GetComponentPizzasByComponentId(int componentId)
        {
            var componentsPizzas = _context.ComponentPizzas.Where(x => x.ComponentId == componentId);

            return componentsPizzas;
        }

        public void DeleteComponentPizzas(int pizzaId, int componentId)
        {
            if (componentId == 0 && pizzaId != 0)
            {
                var componentsPizzasToDelete = _context.ComponentPizzas.Where(x => x.PizzaId == pizzaId);

                _context.RemoveRange(componentsPizzasToDelete);
                _context.SaveChanges();
            }
            else
            {
                var componentsPizzasToDelete = _context.ComponentPizzas.Where(x => x.ComponentId == componentId);

                _context.RemoveRange(componentsPizzasToDelete);
                _context.SaveChanges();
            }
            
        }

        public void EditPizza(Pizza editedPizza)
        {
            List<ComponentPizza> componentPizzas = new List<ComponentPizza>();

            foreach (var item in editedPizza.ComponentPizzas)
            {
                componentPizzas.Add(item);
            }

            _context.Pizzas.Update(editedPizza);
            _context.ComponentPizzas.AddRange(componentPizzas);
            _context.SaveChanges();
        }

        public void UpdatePizzaPrice(List<int> pizzaIds, Component component)
        {
            foreach (var item in pizzaIds)
            {
                var pizza = _context.Pizzas.FirstOrDefault(x => x.Id == item);

                pizza.ComponentsPrice = pizza.ComponentsPrice - component.Price;
                pizza.TotalPrice = pizza.TotalPrice - component.Price;

                _context.Pizzas.Update(pizza);
                _context.SaveChanges();
            }
        }
    }
}
