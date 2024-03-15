namespace PizzeriaImpulsMVC.Application.ViewModels.ShoppingCart;

public class ListShoppingCartVm
{
    public List<ShoppingCartVm> ShoppingCartRows { get; set; }
    public decimal SummaryPrice { get; set; }
}