namespace PizzeriaImpulsMVC.Application.ViewModels.Pizza
{
    public class ListPizzaForListVm
    {
        public List<PizzaForListVm> Pizzas { get; set; }
        public int CurrentPage { get; set; }
        public int PageSize { get; set; }
        public string FilterString { get; set; }
        public int Count { get; set; }
    }
}
