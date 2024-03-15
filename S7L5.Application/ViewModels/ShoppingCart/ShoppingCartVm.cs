namespace PizzeriaImpulsMVC.Application.ViewModels.ShoppingCart;

public class ShoppingCartVm
{
    public int RecordId { get; set; }
    public int CartId { get; set; }
    public int ProductCount { get; set; }
    public int ProductId { get; set; }
    public string ProductName { get; set; }
    public decimal? ProductSize { get; set; }
    public decimal UnitPrice { get; set; }
    public string ProductType { get; set; }
    public string UserName { get; set; }
    public decimal TotalPrice { get; set; }
    public decimal SummaryPrice { get; set; }
    
}