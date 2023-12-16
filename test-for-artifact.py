if __name__ == "__main__":
  app = App(dist="DIST", db="DB")
  app.generateDB()
  app.runQuery()
  app.queryADPRRisk()
  app.outputRisk()
