using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Pizza;

namespace PizzeriaImpulsMVC.Web.Controllers
{
    public class PizzaController : Controller
    {
        private readonly IPizzaService _pizzaService;
        private readonly IComponentService _componentService;

        public PizzaController(IPizzaService pizzaService, IComponentService componentService)
        {
            _pizzaService = pizzaService;
            _componentService = componentService;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Index()
        {

            var pizzas = _pizzaService.GetAllPizzasForList(5, 1, "");

            return View(pizzas);
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Index(int pageSize, int? pageNumber, string filterString)
        {
            if (!pageNumber.HasValue)
            {
                pageNumber = 1;
            }
            if (filterString is null)
            {
                filterString = String.Empty;
            }

            var pizzas = _pizzaService.GetAllPizzasForList(pageSize, pageNumber.Value, filterString);

            return View(pizzas);
        }

        [HttpGet]
        [Route("pizza/add")]
        [Authorize(Roles = "Manager")]
        public IActionResult AddPizza()
        {
            var components = _componentService.GetAllComponents();

            return View(new NewPizzaVm()
            {
                ComponentPizzas = components

            });
        }

        [HttpPost]
        [Route("pizza/add")]
        [Authorize(Roles = "Manager")]
        public IActionResult AddPizza(NewPizzaVm newPizzaVm)
        {
            var checkedComponents = _pizzaService.GetCheckedComponents(newPizzaVm);

            newPizzaVm.ComponentPizzas = checkedComponents;

            int id = _pizzaService.AddPizza(newPizzaVm, 0);

            return RedirectToAction("Index");
        }

        [Authorize(Roles = "Manager")]
        public IActionResult DeletePizza(int pizzaId)
        {
            _pizzaService.DeletePizza(pizzaId);

            return RedirectToAction("Index");
        }

        [HttpGet]
        [Authorize(Roles = "Manager")]
        public IActionResult EditPizza(int pizzaId)
        {
            var pizza = _pizzaService.GetPizzaForEdit(pizzaId);
            var components = _componentService.GetAllComponents();
            var checkedComponents = _pizzaService.UpdateIsCheckStatus(pizza, components);

            pizza.ComponentPizzas = checkedComponents;

            return View(pizza);
        }

        [HttpPost]
        [Authorize(Roles = "Manager")]
        public IActionResult EditPizza(NewPizzaVm newPizzaVm)
        {
            var checkedComponents = _pizzaService.GetCheckedComponents(newPizzaVm);
            newPizzaVm.ComponentPizzas = checkedComponents;

            _pizzaService.EditPizza(newPizzaVm, newPizzaVm.Id);

            return RedirectToAction("Index");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult GetPizzaDetails(int pizzaId)
        {
            var pizza = _pizzaService.GetPizzaDetails(pizzaId);

            return View(pizza);
        }
    }
}
