#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /src
COPY ["src/Services/Victor.Pagamento.API/Victor.Pagamento.API.csproj", "src/Services/Victor.Pagamento.API/"]
RUN dotnet restore "src/Services/Victor.Pagamento.API/Victor.Pagamento.API.csproj"
COPY . .
WORKDIR "/src/src/Services/Victor.Pagamento.API"
RUN dotnet build "Victor.Pagamento.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Victor.Pagamento.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Victor.Pagamento.API.dll"]