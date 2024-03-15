using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Infrastructure.Repositories;

public class ShoppingCartRepository : IShoppingCartRepository
{
    private readonly Context _context;
    
    public ShoppingCartRepository(Context context)
    {
        _context = context;
    }
    
    public List<ShoppingCart> GetShoppingCart(string userName)
    {
        var shoppingCart = _context.ShoppingCarts.Where(u => u.UserId == userName).ToList();

        return shoppingCart;
    }

    public void DeleteRecord(int recordId)
    {
        var shoppingCartRow = _context.ShoppingCarts.Find(recordId);

        if (shoppingCartRow != null)
        {
            _context.ShoppingCarts.Remove(shoppingCartRow);
            _context.SaveChanges();
        }
    }

    public void AddToCart(int productId, string productType, string userName)
    {
        if (productType == "Pizza")
        {
            var cartId = _context.ShoppingCarts.Where(sc => sc.UserId == userName)
                                                .Select(c => c.CartId)
                                                .FirstOrDefault();

            var pizza = _context.Pizzas.FirstOrDefault(a => a.Id == productId);

            if (cartId == 0)
            {
                var shoppingCart = new ShoppingCart()
                {
                    UserId = userName,
                    ProductId = productId,
                    ProductName = pizza.Name,
                    ProductCount = 1,
                    ProductType = productType,
                    UnitPrice = pizza.TotalPrice,
                    Price = pizza.TotalPrice,
                    CreatedAt = DateTime.Now
                };

                _context.ShoppingCarts.Add(shoppingCart);
                _context.SaveChanges();

                var shoppingCartForUpdate = _context.ShoppingCarts.FirstOrDefault(u => u.UserId == userName);
                var id = shoppingCart.RecordId;

                shoppingCartForUpdate.CartId = id;

                _context.Update(shoppingCartForUpdate);
                _context.SaveChanges();
            }
            else
            {
                var shoppingCartProducts = _context.ShoppingCarts.Where(c => c.CartId == cartId);

                if (shoppingCartProducts.Any(scp => scp.ProductId == productId && scp.ProductType == productType))
                {
                    var shoppingCartForUpdate = _context.ShoppingCarts.FirstOrDefault(scp =>
                        scp.ProductId == productId && scp.ProductType == productType);

                    shoppingCartForUpdate.ProductCount += 1;
                    shoppingCartForUpdate.Price += pizza.TotalPrice;

                    _context.Update(shoppingCartForUpdate);
                    _context.SaveChanges();

                }
                else
                {
                    var shoppingCart = new ShoppingCart()
                    {
                        CartId = shoppingCartProducts.FirstOrDefault(scp => scp.UserId == userName).CartId,
                        UserId = userName,
                        ProductId = productId,
                        ProductName = pizza.Name,
                        ProductCount = 1,
                        ProductType = productType,
                        UnitPrice = pizza.TotalPrice,
                        Price = pizza.TotalPrice,
                        CreatedAt = shoppingCartProducts.FirstOrDefault(scp => scp.UserId == userName).CreatedAt
                    };

                    _context.ShoppingCarts.Add(shoppingCart);
                    _context.SaveChanges();
                }
            }
        }
        else if (productType == "Drink")
        {
            var cartId = _context.ShoppingCarts.Where(sc => sc.UserId == userName)
                                                .Select(c => c.CartId)
                                                .FirstOrDefault();

            var drink = _context.Drinks.FirstOrDefault(a => a.Id == productId);

            if (cartId == 0)
            {
                var shoppingCart = new ShoppingCart()
                {
                    UserId = userName,
                    ProductId = productId,
                    ProductName = drink.Name,
                    ProductSize = drink.Size,
                    ProductCount = 1,
                    ProductType = productType,
                    UnitPrice = drink.Price,
                    Price = drink.Price,
                    CreatedAt = DateTime.Now
                };

                _context.ShoppingCarts.Add(shoppingCart);
                _context.SaveChanges();

                var shoppingCartForUpdate = _context.ShoppingCarts.FirstOrDefault(u => u.UserId == userName);
                var id = shoppingCart.RecordId;

                shoppingCartForUpdate.CartId = id;

                _context.Update(shoppingCartForUpdate);
                _context.SaveChanges();
            }
            else
            {
                var shoppingCartProducts = _context.ShoppingCarts.Where(c => c.CartId == cartId);

                if (shoppingCartProducts.Any(scp => scp.ProductId == productId && scp.ProductType == productType))
                {
                    var shoppingCartForUpdate = _context.ShoppingCarts.FirstOrDefault(scp =>
                        scp.ProductId == productId && scp.ProductType == productType);

                    shoppingCartForUpdate.ProductCount += 1;
                    shoppingCartForUpdate.Price += drink.Price;

                    _context.Update(shoppingCartForUpdate);
                    _context.SaveChanges();
                }
                else
                {
                    var shoppingCart = new ShoppingCart()
                    {
                        CartId = shoppingCartProducts.FirstOrDefault(scp => scp.UserId == userName).CartId,
                        UserId = userName,
                        ProductId = productId,
                        ProductName = drink.Name,
                        ProductSize = drink.Size,
                        ProductCount = 1,
                        ProductType = productType,
                        UnitPrice = drink.Price,
                        Price = drink.Price,
                        CreatedAt = shoppingCartProducts.FirstOrDefault(scp => scp.UserId == userName).CreatedAt
                    };

                    _context.ShoppingCarts.Add(shoppingCart);
                    _context.SaveChanges();
                }
            }
        }
        else if(productType == "Addition")
        {
            var cartId = _context.ShoppingCarts.Where(sc => sc.UserId == userName)
                                                .Select(c => c.CartId)
                                                .FirstOrDefault();
            
            var addition = _context.Additions.FirstOrDefault(a => a.Id == productId);

            if (cartId == 0)
            {
                var shoppingCart = new ShoppingCart()
                {
                    UserId = userName,
                    ProductId = productId,
                    ProductName = addition.Name,
                    ProductCount = 1,
                    ProductType = productType,
                    UnitPrice = addition.Price,
                    Price = addition.Price,
                    CreatedAt = DateTime.Now
                };

                _context.ShoppingCarts.Add(shoppingCart);
                _context.SaveChanges();

                var shoppingCartForUpdate = _context.ShoppingCarts.FirstOrDefault(u => u.UserId == userName);
                var id = shoppingCart.RecordId;

                shoppingCartForUpdate.CartId = id;

                _context.Update(shoppingCartForUpdate);
                _context.SaveChanges();
            }
            else
            {
                var shoppingCartProducts = _context.ShoppingCarts.Where(c => c.CartId == cartId);

                if (shoppingCartProducts.Any(scp => scp.ProductId == productId && scp.ProductType == productType))
                {
                    var shoppingCartForUpdate = _context.ShoppingCarts.FirstOrDefault(scp =>
                        scp.ProductId == productId && scp.ProductType == productType);

                    shoppingCartForUpdate.ProductCount += 1;
                    shoppingCartForUpdate.Price += addition.Price;
                    
                    _context.Update(shoppingCartForUpdate);
                    _context.SaveChanges();
                }
                else
                {
                    var shoppingCart = new ShoppingCart()
                    {
                        CartId = shoppingCartProducts.FirstOrDefault(scp => scp.UserId == userName).CartId,
                        UserId = userName,
                        ProductId = productId,
                        ProductName = addition.Name,
                        ProductCount = 1,
                        ProductType = productType,
                        UnitPrice = addition.Price,
                        Price = addition.Price,
                        CreatedAt = shoppingCartProducts.FirstOrDefault(scp => scp.UserId == userName).CreatedAt
                    };

                    _context.ShoppingCarts.Add(shoppingCart);
                    _context.SaveChanges();
                }
            }
        }
    }

    public void Pay(Order order)
    {
        _context.Orders.Add(order);

        var userShoppingCart = _context.ShoppingCarts.Where(u => u.UserId == order.UserName).ToList();
        
        _context.ShoppingCarts.RemoveRange(userShoppingCart);
        _context.SaveChanges();
    }

}