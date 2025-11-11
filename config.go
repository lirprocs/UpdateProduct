package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env    string `yaml:"env"`
	Server `yaml:"http_server"`
}

type Server struct {
	Address   string `yaml:"address"`
	Port      string `yaml:"port"`
	UpdateDir string `yaml:"updateDir"`
}

func MustLoad() *Config {
	cfg := &Config{
		Env: "local",
		Server: Server{
			Address:   "[::]",
			Port:      ":443",
			UpdateDir: "updates",
		},
	}

	configPath := getConfigPath()

	if _, err := os.Stat(configPath); err == nil {
		if err := cleanenv.ReadConfig(configPath, cfg); err != nil {
			log.Printf("Cannot read config file %s: %v, using default values", configPath, err)
		} else {
			log.Printf("Config loaded from: %s", configPath)
		}
	} else {
		log.Printf("Config file does not exist: %s, using default values", configPath)
	}

	return cfg
}

func getConfigPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "env.conf"
	}

	exeDir := filepath.Dir(exePath)

	return filepath.Join(exeDir, "env.conf")
}
