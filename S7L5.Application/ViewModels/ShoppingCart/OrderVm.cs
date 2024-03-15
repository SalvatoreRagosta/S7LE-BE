namespace PizzeriaImpulsMVC.Application.ViewModels.ShoppingCart
{
    public class OrderVm
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string City { get; set; }
        public string Street { get; set; }
        public int HomeNumber { get; set; }
        public int ApartmentNumber { get; set; }
        public decimal Total { get; set; }
        public List<OrderDetailVm> OrderDetailVms { get; set; }
    }
}
