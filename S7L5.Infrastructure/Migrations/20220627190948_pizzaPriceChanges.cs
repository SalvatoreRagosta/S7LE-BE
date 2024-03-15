using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PizzeriaImpulsMVC.Infrastructure.Migrations
{
    public partial class pizzaPriceChanges : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Price",
                table: "Pizzas",
                newName: "UserPrice");

            migrationBuilder.AddColumn<int>(
                name: "ComponentsPrice",
                table: "Pizzas",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "TotalPrice",
                table: "Pizzas",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ComponentsPrice",
                table: "Pizzas");

            migrationBuilder.DropColumn(
                name: "TotalPrice",
                table: "Pizzas");

            migrationBuilder.RenameColumn(
                name: "UserPrice",
                table: "Pizzas",
                newName: "Price");
        }
    }
}
