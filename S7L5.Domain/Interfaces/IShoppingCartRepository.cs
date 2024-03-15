using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Domain.Interfaces;

public interface IShoppingCartRepository
{
    List<ShoppingCart> GetShoppingCart(string userId);
    void DeleteRecord(int recordId);
    void AddToCart(int productId, string productType, string userName);
    void Pay(Order order);
}