package main
import "gopkg.in/hlandau/service.v2"
import "gopkg.in/hlandau/easyconfig.v1"
import "github.com/hlandau/ctmon/server"
import "github.com/hlandau/degoutils/xlogconfig"

func main() {
  cfg := server.Config{}
  config := easyconfig.Configurator{
    ProgramName: "ctmon",
  }
  config.ParseFatal(&cfg)

  xlogconfig.Init()

  service.Main(&service.Info{
    Description: "certificate transparency monitoring daemon",
    DefaultChroot: service.EmptyChrootPath,
    NewFunc: func() (service.Runnable, error) {
      return server.New(cfg)
    },
  })
}
