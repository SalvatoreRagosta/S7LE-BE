using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PizzeriaImpulsMVC.Application.Helpers;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.ShoppingCart;

namespace PizzeriaImpulsMVC.Web.Controllers;

[Authorize]
public class ShoppingCartController : Controller
{
    private readonly IShoppingCartService _shoppingCartService;
    
    public ShoppingCartController(IShoppingCartService shoppingCartService)
    {
        _shoppingCartService = shoppingCartService;

    }
    [HttpGet]
    [Authorize(Roles = "User")]
    public IActionResult Index()
    {
        var userName = HttpContext.User.Identity.Name;
        var shoppingCartVm = _shoppingCartService.GetShoppingCart(userName);
        return View(shoppingCartVm);
    }

    [Authorize(Roles = "User")]
    public IActionResult AddAdditionToCart(int additionId)
    {
        var userName = HttpContext.User.Identity.Name;

        _shoppingCartService.AddToCart(additionId, ProductType.Addition.ToString(), userName);

        return RedirectToAction("Index");
    }

    [Authorize(Roles = "User")]
    public IActionResult AddDrinkToCart(int drinkId)
    {
        var userName = HttpContext.User.Identity.Name;

        _shoppingCartService.AddToCart(drinkId, ProductType.Drink.ToString(), userName);

        return RedirectToAction("Index");

    }

    [Authorize(Roles = "User")]
    public IActionResult AddPizzaToCart(int pizzaId)
    {
        var userName = HttpContext.User.Identity.Name;

        _shoppingCartService.AddToCart(pizzaId, ProductType.Pizza.ToString(), userName);

        return RedirectToAction("Index");
    }

    [Authorize(Roles = "User")]
    public IActionResult DeleteProductFromCart(int recordId)
    {
        _shoppingCartService.DeleteRecord(recordId);

        return RedirectToAction("Index");
    }

    [HttpGet]
    [Route("shoppingCart/makeOrder")]
    [Authorize(Roles = "User")]
    public IActionResult MakeOrder()
    {
        var userName = HttpContext.User.Identity.Name;
        var makeOrderVm = _shoppingCartService.MakeOrder(userName);

        return View(makeOrderVm);
    }

    [HttpPost]
    [Route("shoppingCart/makeOrder")]
    [Authorize(Roles = "User")]
    public IActionResult Pay(OrderVm orderVm)
    {
        var userName = HttpContext.User.Identity.Name;

        orderVm.UserName = userName;

        _shoppingCartService.Pay(orderVm);

        return RedirectToAction("Index");
    }
}