using PizzeriaImpulsMVC.Application.ViewModels.ShoppingCart;

namespace PizzeriaImpulsMVC.Application.Interfaces;

public interface IShoppingCartService
{
    ListShoppingCartVm GetShoppingCart(string userName);
    void DeleteRecord(int recordId);
    void AddToCart(int productId, string productType, string userName);
    OrderVm MakeOrder(string userName);
    void Pay(OrderVm orderVm);
}