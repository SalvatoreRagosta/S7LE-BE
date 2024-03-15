using AutoMapper;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Component;
using PizzeriaImpulsMVC.Application.ViewModels.Pizza;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Application.Services
{
    public class PizzaService : IPizzaService

    {
        private readonly IMapper _mapper;
        private readonly IPizzaRepository _pizzaRepository;
        private readonly IComponentRepository _componentRepository;

        public PizzaService(IMapper mapper, IPizzaRepository pizzaRepository, IComponentRepository componentRepository)
        {
            _mapper = mapper;
            _pizzaRepository = pizzaRepository;
            _componentRepository = componentRepository;
        }

        public ListPizzaForListVm GetAllPizzasForList(int pageSize, int pageNumber, string filterString)
        {
            var pizzas = GetAllPizzas(filterString);

            var pizzasToShow = pizzas.Skip(pageSize*(pageNumber - 1)).Take(pageSize).ToList();

            var pizzasList = new ListPizzaForListVm()
            {
                CurrentPage = pageNumber,
                PageSize = pageSize,
                FilterString = filterString,
                Pizzas = pizzasToShow,
                Count = pizzas.Count
            };

            return pizzasList;
        }
         
        public List<PizzaForListVm> GetAllPizzas(string filterString)
        {
            var pizzas = _pizzaRepository.GetAllPizzas().Where(p => p.Name.Contains(filterString.ToLower()));
            
            var pizzasList = new List<PizzaForListVm>();

            foreach (var item in pizzas)
            {
                var pizzaForListVm = PizzaToPizzaVmMapper(item);
                pizzasList.Add(pizzaForListVm);               
            }

            return pizzasList;
        }

        public int AddPizza(NewPizzaVm newPizzaVm, int pizzaId)
        {
            bool pizzaIsMeat = false;
            int componentsPrice = 0;

            //Creating an intermediate table
            var componentPizzaList = new List<ComponentPizza>();
            if (pizzaId == 0)
            {
                for (int i = 0; i < newPizzaVm.ComponentPizzas.Count; i++)
                {
                    var componentPizza = new ComponentPizza()
                    {
                        PizzaId = newPizzaVm.Id,
                        ComponentId = newPizzaVm.ComponentPizzas[i].Id,

                    };

                    componentPizzaList.Add(componentPizza);
                }
            }
            else
            {
                _pizzaRepository.DeleteComponentPizzas(pizzaId, 0);

                for (int i = 0; i < newPizzaVm.ComponentPizzas.Count; i++)
                {
                    var componentPizza = new ComponentPizza()
                    {
                        PizzaId = newPizzaVm.Id,
                        ComponentId = newPizzaVm.ComponentPizzas[i].Id,

                    };

                    componentPizzaList.Add(componentPizza);
                }
            }
            

            //Checking if pizza is meat
            if (newPizzaVm.ComponentPizzas.Any(c => c.IsMeat == true))
            {
                pizzaIsMeat = true;
            }

            //Calculating the price off components
            for (int i = 0; i < newPizzaVm.ComponentPizzas.Count; i++)
            {
                componentsPrice += newPizzaVm.ComponentPizzas[i].Price;
            }

            //User pirce
            int userPrice = newPizzaVm.Price;

            //Total price
            int totalPrice = componentsPrice + userPrice;

            int id;

            //Final pizza
            if (pizzaId == 0)
            {
                var pizza = new Pizza()
                {
                    UserPrice = userPrice,
                    ComponentsPrice = componentsPrice,
                    TotalPrice = totalPrice,
                    IsMeat = pizzaIsMeat,
                    Name = newPizzaVm.Name,
                    ComponentPizzas = componentPizzaList
                };

                id = _pizzaRepository.AddPizza(pizza);
                return id;
            }
            else
            {
                var pizza = new Pizza()
                {
                    Id = pizzaId,
                    UserPrice = userPrice,
                    ComponentsPrice = componentsPrice,
                    TotalPrice = totalPrice,
                    IsMeat = pizzaIsMeat,
                    Name = newPizzaVm.Name,
                    ComponentPizzas = componentPizzaList
                };

                 _pizzaRepository.EditPizza(pizza);
            }

            return 0;
        }

        public List<ComponentForListVm> GetCheckedComponents(NewPizzaVm newPizzaVm)
        {
            var checkedComponents = new List<ComponentForListVm>();

            for (int i = 0; i < newPizzaVm.ComponentPizzas.Count; i++)
            {
                if (newPizzaVm.ComponentPizzas[i].IsChecked == true)
                {
                    checkedComponents.Add(newPizzaVm.ComponentPizzas[i]);
                }
            }

            return checkedComponents;
        }

        public void DeletePizza(int pizzaId)
        {
            _pizzaRepository.DeletePizza(pizzaId);
        }
        
        public NewPizzaVm GetPizzaForEdit(int pizzaId)
        {
            var pizza = _pizzaRepository.GetPizzaById(pizzaId);

            var pizzaForEdit = new NewPizzaVm()
            {
                Id = pizza.Id,
                Price = pizza.UserPrice,
                IsMeat = pizza.IsMeat,
                Name = pizza.Name,
                ComponentPizzas = pizza.ComponentPizzas
                    .Select(c => new ComponentForListVm()
                    {
                        Id = c.Component.Id,
                        Name = c.Component.Name,
                        IsMeat = c.Component.IsMeat,
                        Price = c.Component.Price,
                    }).ToList()
            };

            return pizzaForEdit;
        }

        public void EditPizza(NewPizzaVm editPizzaVm, int pizzaId)
        {
            AddPizza(editPizzaVm, pizzaId);
        }

        public PizzaForListVm GetPizzaDetails(int pizzaId)
        {
            var pizza = _pizzaRepository.GetPizzaById(pizzaId);
            var pizzaVm = PizzaToPizzaVmMapper(pizza);
            return pizzaVm;
        }

        public PizzaForListVm PizzaToPizzaVmMapper(Pizza pizza)
        {
            var pizzaVm = new PizzaForListVm()
            {
                Id = pizza.Id,
                Price = pizza.TotalPrice,
                Name = pizza.Name,
                IsMeat = pizza.IsMeat,
                ImgPath = pizza.ImgPath,
                Components = pizza.ComponentPizzas
                    .Select(c => new ComponentForListVm()
                    {
                        Id = c.Component.Id,
                        Name = c.Component.Name,
                        IsMeat = c.Component.IsMeat,
                        Price = c.Component.Price,
                    }).ToList()
            };
            return pizzaVm;
        }

        public List<ComponentForListVm> UpdateIsCheckStatus(NewPizzaVm pizza, List<ComponentForListVm> components)
        {
            foreach (var item in pizza.ComponentPizzas)
            {
                for (int i = 0; i < components.Count; i++)
                {
                    if (components[i].Id == item.Id)
                    {
                        components[i].IsChecked = true;
                    }
                }
            }

            return components;
        }
    }
}
