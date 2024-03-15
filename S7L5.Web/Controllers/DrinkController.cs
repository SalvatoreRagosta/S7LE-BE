using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Drink;

namespace PizzeriaImpulsMVC.Web.Controllers
{
    public class DrinkController : Controller
    {
        private readonly IDrinkService _drinkService;

        public DrinkController(IDrinkService drinkService)
        {
            _drinkService = drinkService;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Index()
        {
            var drinks = _drinkService.GetAllDrinksForList(5, 1, "");
            return View(drinks);
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Index(int pageSize, int? pageNumber, string filterString, string ordering)
        {
            if(!pageNumber.HasValue)
            {
                pageNumber = 1;
            }

            if(filterString is null)
            {
                filterString = String.Empty;
            }

            var drinks = _drinkService.GetAllDrinksForList(pageSize, pageNumber.Value, filterString);

            return View(drinks);
        }


        [HttpGet]
        [Route("drink/add")]
        [Authorize(Roles = "Manager")]
        public IActionResult AddDrink()
        {
            return View(new NewDrinkVm());
                
        }

        [HttpPost]
        [Route("drink/add")]
        [Authorize(Roles = "Manager")]
        public IActionResult AddDrink(NewDrinkVm newDrinkVm)
        {

            int id = _drinkService.AddDrink(newDrinkVm);

            return RedirectToAction("Index");
        }

        [Authorize(Roles = "Manager")]
        public IActionResult DeleteDrink(int drinkId)
        {
            _drinkService.DeleteDrink(drinkId);

            return RedirectToAction("Index");
        }

        [HttpGet]
        [Authorize(Roles = "Manager")]
        public IActionResult EditDrink(int drinkId)
        {
            var drink = _drinkService.GetDrinkForEdit(drinkId);

            return View(drink);
        }

        [HttpPost]
        [Authorize(Roles = "Manager")]
        public IActionResult EditDrink(NewDrinkVm editDrinkVm)
        {
            _drinkService.EditDrink(editDrinkVm);

            return RedirectToAction("Index");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult GetDrinkDetails(int drinkId)
        {
            var drink = _drinkService.GetDrinkDetails(drinkId);

            return View(drink);
        }
    }
}
