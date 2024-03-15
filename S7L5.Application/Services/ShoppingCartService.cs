using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.ShoppingCart;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Application.Services;

public class ShoppingCartService : IShoppingCartService
{
    private readonly IShoppingCartRepository _shoppingCartRepository;
    private readonly IUserManagmentService _userManagmentService;
    
    public ShoppingCartService(IShoppingCartRepository shoppingCartRepository, IUserManagmentService userManagmentService)
    {
        _shoppingCartRepository = shoppingCartRepository;
        _userManagmentService = userManagmentService;
    }
    public ListShoppingCartVm GetShoppingCart(string userId)
    {
        List<ShoppingCartVm> shoppingCartRows = new List<ShoppingCartVm>();
       

        var shoppingCart = _shoppingCartRepository.GetShoppingCart(userId);

        foreach (var shoppingCartRow in shoppingCart)
        {
            var shoppingCartVm = new ShoppingCartVm()
            {
                RecordId = shoppingCartRow.RecordId,
                CartId = shoppingCartRow.CartId,
                ProductCount = shoppingCartRow.ProductCount,
                ProductId = shoppingCartRow.ProductId,
                ProductName = shoppingCartRow.ProductName,
                ProductSize = shoppingCartRow.ProductSize,
                UnitPrice = shoppingCartRow.UnitPrice,
                TotalPrice = shoppingCartRow.Price,
                ProductType = shoppingCartRow.ProductType
            };

            shoppingCartRows.Add(shoppingCartVm);
        }

        var listShoppingCartVm = new ListShoppingCartVm();

        listShoppingCartVm.ShoppingCartRows = shoppingCartRows;
        listShoppingCartVm.SummaryPrice = shoppingCartRows.Sum(p => p.TotalPrice);

        return listShoppingCartVm;
    }

    public void DeleteRecord(int recordId)
    {
        _shoppingCartRepository.DeleteRecord(recordId);
    }

    public void AddToCart(int productId, string productType, string userName)
    {
        _shoppingCartRepository.AddToCart(productId, productType, userName);
    }

    public OrderVm MakeOrder(string userName)
    {
        var userShoppingCart = _shoppingCartRepository.GetShoppingCart(userName);
        var userDetails = _userManagmentService.GetUserByUserName(userName);

        var price = userShoppingCart.Sum(p => p.Price);

        var orderVm = new OrderVm()
        {
            FirstName = userDetails.FirstName,
            LastName = userDetails.LastName,
            City = userDetails.City,
            Street = userDetails.Street,
            HomeNumber = userDetails.HomeNumber,
            ApartmentNumber = userDetails.ApartmentNumber,
            Total = price,
            OrderDetailVms = userShoppingCart
                .Select(o => new OrderDetailVm()
                {
                    OrderId = o.CartId,
                    UserName = o.UserId,
                    ProductId = o.ProductId,
                    ProductName = o.ProductName,
                    ProductSize = o.ProductSize,
                    ProductCount = o.ProductCount,
                    ProductType = o.ProductType,
                    UnitPrice = o.UnitPrice,
                    Price = o.Price,
                    CreatedAt = o.CreatedAt
                }).ToList()
        };

        return orderVm;
    }

    public void Pay(OrderVm orderVm)
    {
        var orderFromDb = MakeOrder(orderVm.UserName);

        List<OrderDetail> orderDetails = new List<OrderDetail>();

        foreach (var item in orderFromDb.OrderDetailVms)
        {
            OrderDetail orderDetailVm = new OrderDetail()
            {
                ProductCount = item.ProductCount,
                ProductId = item.ProductId,
                UnitPrice = item.UnitPrice,
                CreatedAt = item.CreatedAt,
                Price = item.Price,
                ProductName = item.ProductName,
                ProductSize = item.ProductSize,
                ProductType = item.ProductType
            };

            orderDetails.Add(orderDetailVm);
        }

        Order order = new Order()
        {
            UserName = orderVm.UserName,
            FirstName = orderVm.FirstName,
            LastName = orderVm.LastName,
            City = orderVm.City,
            Street = orderVm.Street,
            HomeNumber = orderVm.HomeNumber,
            ApartmentNumber = orderVm.ApartmentNumber,
            Total = orderDetails.Sum(p => p.Price),
            OrderDate = DateTime.Now,
            OrderDetails = orderDetails

        };

        _shoppingCartRepository.Pay(order);
    }
}